rule TTP_XOR_WriteProcessMemory_f317 {
  strings:
    $key_f317 = { a4 65 [2] 96 47 [2] 90 72 [2] be 72 [2] 81 6e }

  condition:
    any of them
}