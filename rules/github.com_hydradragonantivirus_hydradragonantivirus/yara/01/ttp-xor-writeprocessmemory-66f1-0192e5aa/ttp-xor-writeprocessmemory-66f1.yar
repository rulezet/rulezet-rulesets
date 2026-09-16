rule TTP_XOR_WriteProcessMemory_66f1 {
  strings:
    $key_66f1 = { 31 83 [2] 03 a1 [2] 05 94 [2] 2b 94 [2] 14 88 }

  condition:
    any of them
}