import "pe"
rule tElockv085f_ren: tE {
  meta:
    author = "_pusher_"
    date   = "2015-11"

  strings:
    $a0 = { 60 E8 02 ?? ?? ?? CD 20 E8 ?? ?? ?? ?? 5E 2B C9 58 74 02 CD 20 B9 }

  condition:
    $a0 at pe.entry_point
}