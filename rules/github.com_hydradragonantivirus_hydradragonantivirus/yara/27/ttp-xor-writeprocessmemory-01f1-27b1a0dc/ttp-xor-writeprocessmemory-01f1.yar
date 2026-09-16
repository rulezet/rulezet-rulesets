rule TTP_XOR_WriteProcessMemory_01f1 {
  strings:
    $key_01f1 = { 56 83 [2] 64 a1 [2] 62 94 [2] 4c 94 [2] 73 88 }

  condition:
    any of them
}