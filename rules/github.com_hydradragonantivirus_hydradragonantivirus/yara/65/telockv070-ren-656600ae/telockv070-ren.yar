import "pe"
rule tElockv070_ren: tE {
  meta:
    author = "_pusher_"
    date   = "2015-11"

  strings:
    $a0 = { 60 E8 BD 10 ?? ?? C3 83 }

  condition:
    $a0 at pe.entry_point
}