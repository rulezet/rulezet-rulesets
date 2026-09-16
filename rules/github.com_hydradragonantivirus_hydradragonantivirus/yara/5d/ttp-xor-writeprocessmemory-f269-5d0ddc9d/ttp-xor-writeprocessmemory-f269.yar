rule TTP_XOR_WriteProcessMemory_f269 {
  strings:
    $key_f269 = { a5 1b [2] 97 39 [2] 91 0c [2] bf 0c [2] 80 10 }

  condition:
    any of them
}