rule TTP_XOR_WriteProcessMemory_f103 {
  strings:
    $key_f103 = { a6 71 [2] 94 53 [2] 92 66 [2] bc 66 [2] 83 7a }

  condition:
    any of them
}