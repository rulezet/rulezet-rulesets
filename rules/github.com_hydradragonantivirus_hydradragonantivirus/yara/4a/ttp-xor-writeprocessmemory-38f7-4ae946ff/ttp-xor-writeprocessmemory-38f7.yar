rule TTP_XOR_WriteProcessMemory_38f7 {
  strings:
    $key_38f7 = { 6f 85 [2] 5d a7 [2] 5b 92 [2] 75 92 [2] 4a 8e }

  condition:
    any of them
}