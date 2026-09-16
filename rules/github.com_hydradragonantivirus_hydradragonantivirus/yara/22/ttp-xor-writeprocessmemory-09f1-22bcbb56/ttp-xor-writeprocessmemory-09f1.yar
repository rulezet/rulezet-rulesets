rule TTP_XOR_WriteProcessMemory_09f1 {
  strings:
    $key_09f1 = { 5e 83 [2] 6c a1 [2] 6a 94 [2] 44 94 [2] 7b 88 }

  condition:
    any of them
}