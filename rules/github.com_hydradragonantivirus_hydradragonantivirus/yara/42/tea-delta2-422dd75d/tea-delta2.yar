rule TEA_DELTA2 {
  meta:
    author      = "_pusher_"
    description = "TEA DELTA"
    date        = "2016-02"

  strings:
    $c0 = { 9E 37 79 B9 }
    $c1 = { 61 C8 86 47 }

  condition:
    any of them
}