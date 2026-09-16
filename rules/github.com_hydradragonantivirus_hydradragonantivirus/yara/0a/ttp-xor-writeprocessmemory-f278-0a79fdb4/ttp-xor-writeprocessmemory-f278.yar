rule TTP_XOR_WriteProcessMemory_f278 {
  strings:
    $key_f278 = { a5 0a [2] 97 28 [2] 91 1d [2] bf 1d [2] 80 01 }

  condition:
    any of them
}