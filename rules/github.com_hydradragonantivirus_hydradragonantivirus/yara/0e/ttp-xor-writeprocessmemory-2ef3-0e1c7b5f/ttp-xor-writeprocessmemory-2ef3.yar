rule TTP_XOR_WriteProcessMemory_2ef3 {
  strings:
    $key_2ef3 = { 79 81 [2] 4b a3 [2] 4d 96 [2] 63 96 [2] 5c 8a }

  condition:
    any of them
}