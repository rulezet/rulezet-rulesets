rule TTP_XOR_WriteProcessMemory_f2fe {
  strings:
    $key_f2fe = { a5 8c [2] 97 ae [2] 91 9b [2] bf 9b [2] 80 87 }

  condition:
    any of them
}