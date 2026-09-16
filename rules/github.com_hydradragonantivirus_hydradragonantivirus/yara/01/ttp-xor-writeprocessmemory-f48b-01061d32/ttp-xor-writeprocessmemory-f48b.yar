rule TTP_XOR_WriteProcessMemory_f48b {
  strings:
    $key_f48b = { a3 f9 [2] 91 db [2] 97 ee [2] b9 ee [2] 86 f2 }

  condition:
    any of them
}