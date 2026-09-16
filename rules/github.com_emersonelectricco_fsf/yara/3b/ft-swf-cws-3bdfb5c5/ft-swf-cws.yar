rule ft_swf_cws
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150318"
      desc = "File type signature for regular compressed SWF files"

   strings:
      $cws = "CWS"

   condition:
      $cws at 0
}