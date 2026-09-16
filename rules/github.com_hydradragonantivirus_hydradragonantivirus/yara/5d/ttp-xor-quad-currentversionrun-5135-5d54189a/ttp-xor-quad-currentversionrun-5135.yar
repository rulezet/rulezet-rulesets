rule TTP_XOR_QUAD_CurrentVersionRun_5135 {
  strings:
    $key_5135 = { 02 5a [2] 26 54 [2] 0d 78 [2] 23 5a [2] 37 41 [2] 38 5b [2] 26 46 [2] 24 47 [2] 3f 41 [2] 23 46 [2] 3f 69 }

  condition:
    any of them
}