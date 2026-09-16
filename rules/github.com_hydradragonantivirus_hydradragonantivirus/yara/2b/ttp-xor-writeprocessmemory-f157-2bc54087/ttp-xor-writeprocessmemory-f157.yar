rule TTP_XOR_WriteProcessMemory_f157 {
  strings:
    $key_f157 = { a6 25 [2] 94 07 [2] 92 32 [2] bc 32 [2] 83 2e }

  condition:
    any of them
}