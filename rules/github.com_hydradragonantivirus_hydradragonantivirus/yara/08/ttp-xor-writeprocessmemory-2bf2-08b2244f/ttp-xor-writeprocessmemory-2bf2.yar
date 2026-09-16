rule TTP_XOR_WriteProcessMemory_2bf2 {
  strings:
    $key_2bf2 = { 7c 80 [2] 4e a2 [2] 48 97 [2] 66 97 [2] 59 8b }

  condition:
    any of them
}