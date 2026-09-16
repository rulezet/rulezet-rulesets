rule TTP_XOR_WriteProcessMemory_f209 {
  strings:
    $key_f209 = { a5 7b [2] 97 59 [2] 91 6c [2] bf 6c [2] 80 70 }

  condition:
    any of them
}