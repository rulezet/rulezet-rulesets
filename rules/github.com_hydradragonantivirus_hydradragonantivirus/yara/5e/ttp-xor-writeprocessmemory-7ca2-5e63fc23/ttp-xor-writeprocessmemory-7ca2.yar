rule TTP_XOR_WriteProcessMemory_7ca2 {
  strings:
    $key_7ca2 = { 2b d0 [2] 19 f2 [2] 1f c7 [2] 31 c7 [2] 0e db }

  condition:
    any of them
}