rule TTP_XOR_WriteProcessMemory_0ef3 {
  strings:
    $key_0ef3 = { 59 81 [2] 6b a3 [2] 6d 96 [2] 43 96 [2] 7c 8a }

  condition:
    any of them
}