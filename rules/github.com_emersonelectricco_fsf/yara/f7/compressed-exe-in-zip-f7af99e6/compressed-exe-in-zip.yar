rule compressed_exe_in_zip
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150813"
      desc = "Detect on evidence of a compressed executable within a ZIP"

   strings:
      $pk = { 50 4B 03 04 }
      $exe_ext = ".exe"

   condition:
      $pk at 0 and for any p in (1..#pk):
                                    ($exe_ext in (@pk[p] + 30..@pk[p] + 30 + uint16(@pk[p] + 26)))
}