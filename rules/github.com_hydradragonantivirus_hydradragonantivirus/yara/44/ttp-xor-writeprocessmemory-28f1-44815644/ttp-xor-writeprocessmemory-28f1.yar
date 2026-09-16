rule TTP_XOR_WriteProcessMemory_28f1 {
  strings:
    $key_28f1 = { 7f 83 [2] 4d a1 [2] 4b 94 [2] 65 94 [2] 5a 88 }

  condition:
    any of them
}