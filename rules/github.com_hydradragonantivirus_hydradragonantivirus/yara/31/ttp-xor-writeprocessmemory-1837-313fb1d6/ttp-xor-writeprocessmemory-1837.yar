rule TTP_XOR_WriteProcessMemory_1837 {
  strings:
    $key_1837 = { 4f 45 [2] 7d 67 [2] 7b 52 [2] 55 52 [2] 6a 4e }

  condition:
    any of them
}