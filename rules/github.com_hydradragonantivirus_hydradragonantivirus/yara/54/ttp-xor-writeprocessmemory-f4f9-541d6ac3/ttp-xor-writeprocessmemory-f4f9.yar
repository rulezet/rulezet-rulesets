rule TTP_XOR_WriteProcessMemory_f4f9 {
  strings:
    $key_f4f9 = { a3 8b [2] 91 a9 [2] 97 9c [2] b9 9c [2] 86 80 }

  condition:
    any of them
}