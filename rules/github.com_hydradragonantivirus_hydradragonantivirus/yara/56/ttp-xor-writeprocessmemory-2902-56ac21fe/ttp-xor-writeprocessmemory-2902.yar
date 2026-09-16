rule TTP_XOR_WriteProcessMemory_2902 {
  strings:
    $key_2902 = { 7e 70 [2] 4c 52 [2] 4a 67 [2] 64 67 [2] 5b 7b }

  condition:
    any of them
}