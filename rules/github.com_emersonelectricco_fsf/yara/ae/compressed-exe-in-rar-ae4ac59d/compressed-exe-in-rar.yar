rule compressed_exe_in_rar
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150813"
      desc = "Detect on evidence of a compressed executable within a RAR"

   strings:
      $rar = { 52 61 72 21 1A 07 00 }
      $file_header_part = { 74 [12] ( 00 | 01 | 02 | 03 | 04 | 05 ) [9] ( 30 | 31 | 32 | 33 | 34 | 35 ) }
      $exe_ext = ".exe"

   condition:
      $rar at 0 and for any r in (1..#file_header_part):
                                             ($exe_ext in (@file_header_part[r] + 30..@file_header_part[r] + 30 + uint16(@file_header_part[r] + 24)))
}