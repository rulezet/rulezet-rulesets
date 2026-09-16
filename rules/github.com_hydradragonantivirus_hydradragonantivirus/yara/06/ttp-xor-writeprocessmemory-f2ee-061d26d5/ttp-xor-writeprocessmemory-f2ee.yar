rule TTP_XOR_WriteProcessMemory_f2ee {
  strings:
    $key_f2ee = { a5 9c [2] 97 be [2] 91 8b [2] bf 8b [2] 80 97 }

  condition:
    any of them
}