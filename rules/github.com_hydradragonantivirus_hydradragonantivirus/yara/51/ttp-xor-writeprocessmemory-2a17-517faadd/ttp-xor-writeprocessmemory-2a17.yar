rule TTP_XOR_WriteProcessMemory_2a17 {
  strings:
    $key_2a17 = { 7d 65 [2] 4f 47 [2] 49 72 [2] 67 72 [2] 58 6e }

  condition:
    any of them
}