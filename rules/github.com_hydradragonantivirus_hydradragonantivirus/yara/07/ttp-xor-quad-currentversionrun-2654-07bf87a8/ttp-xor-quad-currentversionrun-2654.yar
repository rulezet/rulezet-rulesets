rule TTP_XOR_QUAD_CurrentVersionRun_2654 {
  strings:
    $key_2654 = { 75 3b [2] 51 35 [2] 7a 19 [2] 54 3b [2] 40 20 [2] 4f 3a [2] 51 27 [2] 53 26 [2] 48 20 [2] 54 27 [2] 48 08 }

  condition:
    any of them
}