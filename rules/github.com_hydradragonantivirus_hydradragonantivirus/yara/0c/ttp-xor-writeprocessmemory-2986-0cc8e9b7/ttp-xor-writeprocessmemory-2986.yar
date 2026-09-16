rule TTP_XOR_WriteProcessMemory_2986 {
  strings:
    $key_2986 = { 7e f4 [2] 4c d6 [2] 4a e3 [2] 64 e3 [2] 5b ff }

  condition:
    any of them
}