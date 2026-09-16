rule TTP_XOR_WriteProcessMemory_f468 {
  strings:
    $key_f468 = { a3 1a [2] 91 38 [2] 97 0d [2] b9 0d [2] 86 11 }

  condition:
    any of them
}