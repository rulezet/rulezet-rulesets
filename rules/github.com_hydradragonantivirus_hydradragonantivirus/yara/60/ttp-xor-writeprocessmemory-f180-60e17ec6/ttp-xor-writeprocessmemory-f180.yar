rule TTP_XOR_WriteProcessMemory_f180 {
  strings:
    $key_f180 = { a6 f2 [2] 94 d0 [2] 92 e5 [2] bc e5 [2] 83 f9 }

  condition:
    any of them
}