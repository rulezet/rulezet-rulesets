rule TTP_XOR_WriteProcessMemory_7ef7 {
  strings:
    $key_7ef7 = { 29 85 [2] 1b a7 [2] 1d 92 [2] 33 92 [2] 0c 8e }

  condition:
    any of them
}