rule tElockv090_ren: tE {
  meta:
    author = "_pusher_"
    date   = "2015-11"

  strings:
    $a0 = { ?? ?? E8 02 ?? ?? ?? E8 ?? E8 ?? ?? ?? ?? 5E 2B C9 58 74 02 CD 20 B9 FF 10 }

  condition:
    $a0
}