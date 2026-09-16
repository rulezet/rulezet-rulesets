rule ft_swf_zws
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150318"
      desc = "File type signature for SWF files compressed with LZMA compression, uncommonly observed"

   strings:
      $zws = "ZWS"

   condition:
      $zws at 0
}