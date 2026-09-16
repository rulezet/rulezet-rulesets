rule TTP_XOR_WriteProcessMemory_2985 {
  strings:
    $key_2985 = { 7e f7 [2] 4c d5 [2] 4a e0 [2] 64 e0 [2] 5b fc }

  condition:
    any of them
}