rule TTP_XOR_WriteProcessMemory_2bf3 {
  strings:
    $key_2bf3 = { 7c 81 [2] 4e a3 [2] 48 96 [2] 66 96 [2] 59 8a }

  condition:
    any of them
}