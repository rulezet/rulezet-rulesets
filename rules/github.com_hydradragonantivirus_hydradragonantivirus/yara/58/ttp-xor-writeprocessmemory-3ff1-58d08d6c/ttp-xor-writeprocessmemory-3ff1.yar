rule TTP_XOR_WriteProcessMemory_3ff1 {
  strings:
    $key_3ff1 = { 68 83 [2] 5a a1 [2] 5c 94 [2] 72 94 [2] 4d 88 }

  condition:
    any of them
}