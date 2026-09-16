rule TTP_XOR_WriteProcessMemory_3ef3 {
  strings:
    $key_3ef3 = { 69 81 [2] 5b a3 [2] 5d 96 [2] 73 96 [2] 4c 8a }

  condition:
    any of them
}