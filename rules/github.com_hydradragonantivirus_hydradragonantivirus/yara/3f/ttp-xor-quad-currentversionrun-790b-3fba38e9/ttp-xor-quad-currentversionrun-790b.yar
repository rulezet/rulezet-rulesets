rule TTP_XOR_QUAD_CurrentVersionRun_790b {
  strings:
    $key_790b = { 2a 64 [2] 0e 6a [2] 25 46 [2] 0b 64 [2] 1f 7f [2] 10 65 [2] 0e 78 [2] 0c 79 [2] 17 7f [2] 0b 78 [2] 17 57 }

  condition:
    any of them
}