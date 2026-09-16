rule TTP_XOR_WriteProcessMemory_f347 {
  strings:
    $key_f347 = { a4 35 [2] 96 17 [2] 90 22 [2] be 22 [2] 81 3e }

  condition:
    any of them
}