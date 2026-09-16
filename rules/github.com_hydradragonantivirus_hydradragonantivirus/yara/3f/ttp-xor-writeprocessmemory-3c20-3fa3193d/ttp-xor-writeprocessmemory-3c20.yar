rule TTP_XOR_WriteProcessMemory_3c20 {
  strings:
    $key_3c20 = { 6b 52 [2] 59 70 [2] 5f 45 [2] 71 45 [2] 4e 59 }

  condition:
    any of them
}