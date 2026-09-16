rule TTP_XOR_WriteProcessMemory_3902 {
  strings:
    $key_3902 = { 6e 70 [2] 5c 52 [2] 5a 67 [2] 74 67 [2] 4b 7b }

  condition:
    any of them
}