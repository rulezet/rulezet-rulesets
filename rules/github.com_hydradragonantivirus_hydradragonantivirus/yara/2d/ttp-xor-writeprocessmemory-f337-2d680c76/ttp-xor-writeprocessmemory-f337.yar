rule TTP_XOR_WriteProcessMemory_f337 {
  strings:
    $key_f337 = { a4 45 [2] 96 67 [2] 90 52 [2] be 52 [2] 81 4e }

  condition:
    any of them
}