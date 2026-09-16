rule TTP_XOR_WriteProcessMemory_f219 {
  strings:
    $key_f219 = { a5 6b [2] 97 49 [2] 91 7c [2] bf 7c [2] 80 60 }

  condition:
    any of them
}