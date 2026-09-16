rule TTP_XOR_WriteProcessMemory_38f2 {
  strings:
    $key_38f2 = { 6f 80 [2] 5d a2 [2] 5b 97 [2] 75 97 [2] 4a 8b }

  condition:
    any of them
}