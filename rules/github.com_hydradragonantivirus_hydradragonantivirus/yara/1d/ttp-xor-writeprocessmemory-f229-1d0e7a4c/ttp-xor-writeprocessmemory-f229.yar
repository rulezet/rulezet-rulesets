rule TTP_XOR_WriteProcessMemory_f229 {
  strings:
    $key_f229 = { a5 5b [2] 97 79 [2] 91 4c [2] bf 4c [2] 80 50 }

  condition:
    any of them
}