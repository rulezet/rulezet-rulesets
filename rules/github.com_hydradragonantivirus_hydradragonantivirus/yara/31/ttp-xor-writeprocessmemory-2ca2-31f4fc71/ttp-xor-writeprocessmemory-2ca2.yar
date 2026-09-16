rule TTP_XOR_WriteProcessMemory_2ca2 {
  strings:
    $key_2ca2 = { 7b d0 [2] 49 f2 [2] 4f c7 [2] 61 c7 [2] 5e db }

  condition:
    any of them
}