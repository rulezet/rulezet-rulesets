rule TTP_XOR_WriteProcessMemory_f289 {
  strings:
    $key_f289 = { a5 fb [2] 97 d9 [2] 91 ec [2] bf ec [2] 80 f0 }

  condition:
    any of them
}