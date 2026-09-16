rule ft_swf_fws
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20150318"
      desc = "File type signature for basic SWF files."

   strings:
      $fws = "FWS"

   condition:
      $fws at 0
}