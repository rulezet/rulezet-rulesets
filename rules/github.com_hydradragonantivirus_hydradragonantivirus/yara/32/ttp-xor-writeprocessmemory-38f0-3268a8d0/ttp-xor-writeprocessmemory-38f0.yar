rule TTP_XOR_WriteProcessMemory_38f0 {
  strings:
    $key_38f0 = { 6f 82 [2] 5d a0 [2] 5b 95 [2] 75 95 [2] 4a 89 }

  condition:
    any of them
}