rule TTP_XOR_WriteProcessMemory_f228 {
  strings:
    $key_f228 = { a5 5a [2] 97 78 [2] 91 4d [2] bf 4d [2] 80 51 }

  condition:
    any of them
}