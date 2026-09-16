rule TTP_XOR_WriteProcessMemory_f4e9 {
  strings:
    $key_f4e9 = { a3 9b [2] 91 b9 [2] 97 8c [2] b9 8c [2] 86 90 }

  condition:
    any of them
}