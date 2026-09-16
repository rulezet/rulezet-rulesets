rule TTP_XOR_QUAD_CurrentVersionRun_6a2b {
  strings:
    $key_6a2b = { 39 44 [2] 1d 4a [2] 36 66 [2] 18 44 [2] 0c 5f [2] 03 45 [2] 1d 58 [2] 1f 59 [2] 04 5f [2] 18 58 [2] 04 77 }

  condition:
    any of them
}