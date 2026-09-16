rule TTP_XOR_WriteProcessMemory_f448 {
  strings:
    $key_f448 = { a3 3a [2] 91 18 [2] 97 2d [2] b9 2d [2] 86 31 }

  condition:
    any of them
}