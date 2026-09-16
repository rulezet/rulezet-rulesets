rule TTP_XOR_WriteProcessMemory_f489 {
  strings:
    $key_f489 = { a3 fb [2] 91 d9 [2] 97 ec [2] b9 ec [2] 86 f0 }

  condition:
    any of them
}