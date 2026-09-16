rule TTP_XOR_WriteProcessMemory_f186 {
  strings:
    $key_f186 = { a6 f4 [2] 94 d6 [2] 92 e3 [2] bc e3 [2] 83 ff }

  condition:
    any of them
}