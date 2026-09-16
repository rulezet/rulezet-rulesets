rule TTP_XOR_WriteProcessMemory_02a2 {
  strings:
    $key_02a2 = { 55 d0 [2] 67 f2 [2] 61 c7 [2] 4f c7 [2] 70 db }

  condition:
    any of them
}