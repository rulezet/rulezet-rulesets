rule TTP_XOR_WriteProcessMemory_f435 {
  strings:
    $key_f435 = { a3 47 [2] 91 65 [2] 97 50 [2] b9 50 [2] 86 4c }

  condition:
    any of them
}