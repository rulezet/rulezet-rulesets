rule TTP_XOR_WriteProcessMemory_0802 {
  strings:
    $key_0802 = { 5f 70 [2] 6d 52 [2] 6b 67 [2] 45 67 [2] 7a 7b }

  condition:
    any of them
}