rule TTP_XOR_WriteProcessMemory_38f1 {
  strings:
    $key_38f1 = { 6f 83 [2] 5d a1 [2] 5b 94 [2] 75 94 [2] 4a 88 }

  condition:
    any of them
}