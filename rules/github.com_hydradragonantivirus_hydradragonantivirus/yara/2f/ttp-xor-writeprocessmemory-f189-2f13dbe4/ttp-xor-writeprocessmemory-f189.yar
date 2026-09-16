rule TTP_XOR_WriteProcessMemory_f189 {
  strings:
    $key_f189 = { a6 fb [2] 94 d9 [2] 92 ec [2] bc ec [2] 83 f0 }

  condition:
    any of them
}