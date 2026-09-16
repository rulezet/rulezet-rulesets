rule TTP_XOR_QUAD_CurrentVersionRun_020b {
  strings:
    $key_020b = { 51 64 [2] 75 6a [2] 5e 46 [2] 70 64 [2] 64 7f [2] 6b 65 [2] 75 78 [2] 77 79 [2] 6c 7f [2] 70 78 [2] 6c 57 }

  condition:
    any of them
}