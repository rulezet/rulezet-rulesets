rule TTP_XOR_QUAD_CurrentVersionRun_2678 {
  strings:
    $key_2678 = { 75 17 [2] 51 19 [2] 7a 35 [2] 54 17 [2] 40 0c [2] 4f 16 [2] 51 0b [2] 53 0a [2] 48 0c [2] 54 0b [2] 48 24 }

  condition:
    any of them
}