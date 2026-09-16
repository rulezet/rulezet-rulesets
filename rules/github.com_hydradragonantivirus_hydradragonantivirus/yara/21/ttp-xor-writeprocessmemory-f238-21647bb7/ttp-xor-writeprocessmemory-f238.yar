rule TTP_XOR_WriteProcessMemory_f238 {
  strings:
    $key_f238 = { a5 4a [2] 97 68 [2] 91 5d [2] bf 5d [2] 80 41 }

  condition:
    any of them
}