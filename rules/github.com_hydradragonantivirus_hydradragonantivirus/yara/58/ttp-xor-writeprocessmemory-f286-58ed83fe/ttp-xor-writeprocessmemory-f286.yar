rule TTP_XOR_WriteProcessMemory_f286 {
  strings:
    $key_f286 = { a5 f4 [2] 97 d6 [2] 91 e3 [2] bf e3 [2] 80 ff }

  condition:
    any of them
}