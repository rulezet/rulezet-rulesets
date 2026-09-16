rule TTP_XOR_QUAD_CurrentVersionRun_2644 {
  strings:
    $key_2644 = { 75 2b [2] 51 25 [2] 7a 09 [2] 54 2b [2] 40 30 [2] 4f 2a [2] 51 37 [2] 53 36 [2] 48 30 [2] 54 37 [2] 48 18 }

  condition:
    any of them
}