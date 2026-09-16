rule TTP_XOR_QUAD_CurrentVersionRun_3f54 {
  strings:
    $key_3f54 = { 6c 3b [2] 48 35 [2] 63 19 [2] 4d 3b [2] 59 20 [2] 56 3a [2] 48 27 [2] 4a 26 [2] 51 20 [2] 4d 27 [2] 51 08 }

  condition:
    any of them
}