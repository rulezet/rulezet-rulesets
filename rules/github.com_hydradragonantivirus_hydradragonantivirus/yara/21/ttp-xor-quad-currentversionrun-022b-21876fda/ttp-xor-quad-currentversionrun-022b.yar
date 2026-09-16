rule TTP_XOR_QUAD_CurrentVersionRun_022b {
  strings:
    $key_022b = { 51 44 [2] 75 4a [2] 5e 66 [2] 70 44 [2] 64 5f [2] 6b 45 [2] 75 58 [2] 77 59 [2] 6c 5f [2] 70 58 [2] 6c 77 }

  condition:
    any of them
}