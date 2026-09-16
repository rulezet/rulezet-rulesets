rule Typhoon_Downloader
{
meta:
  author = "Cylance"
  description = "Typhoon downloader"
  reference = "https://www.cylance.com/en_us/blog/baijiu.html"
strings:
  $ps = "<<<:resource"
  $exp = "start_adobeup"
  $e = "W78D432S34A9"
  $f = "!SJ1B0RSWRKK"
  $b = "wyy}EBB"
  $geo = "hhhCjzbnvyvzlCg}B"
condition:
  $ps or $exp or ($e and $f) or $b or $geo
}