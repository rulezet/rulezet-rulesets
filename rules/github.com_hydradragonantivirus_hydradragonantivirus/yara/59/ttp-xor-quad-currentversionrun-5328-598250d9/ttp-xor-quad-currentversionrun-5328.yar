rule TTP_XOR_QUAD_CurrentVersionRun_5328 {
  strings:
    $key_5328 = { 00 47 [2] 24 49 [2] 0f 65 [2] 21 47 [2] 35 5c [2] 3a 46 [2] 24 5b [2] 26 5a [2] 3d 5c [2] 21 5b [2] 3d 74 }

  condition:
    any of them
}