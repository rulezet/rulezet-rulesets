rule TTP_XOR_WriteProcessMemory_f442 {
  strings:
    $key_f442 = { a3 30 [2] 91 12 [2] 97 27 [2] b9 27 [2] 86 3b }

  condition:
    any of them
}