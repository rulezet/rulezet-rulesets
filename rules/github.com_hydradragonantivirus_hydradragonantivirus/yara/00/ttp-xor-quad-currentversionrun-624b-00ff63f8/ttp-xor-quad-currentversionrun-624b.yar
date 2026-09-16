rule TTP_XOR_QUAD_CurrentVersionRun_624b {
  strings:
    $key_624b = { 31 24 [2] 15 2a [2] 3e 06 [2] 10 24 [2] 04 3f [2] 0b 25 [2] 15 38 [2] 17 39 [2] 0c 3f [2] 10 38 [2] 0c 17 }

  condition:
    any of them
}