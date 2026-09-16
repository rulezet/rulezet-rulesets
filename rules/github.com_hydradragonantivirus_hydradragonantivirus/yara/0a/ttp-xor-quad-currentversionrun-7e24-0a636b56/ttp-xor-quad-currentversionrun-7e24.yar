rule TTP_XOR_QUAD_CurrentVersionRun_7e24 {
  strings:
    $key_7e24 = { 2d 4b [2] 09 45 [2] 22 69 [2] 0c 4b [2] 18 50 [2] 17 4a [2] 09 57 [2] 0b 56 [2] 10 50 [2] 0c 57 [2] 10 78 }

  condition:
    any of them
}