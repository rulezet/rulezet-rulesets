rule TTP_XOR_WriteProcessMemory_f43d {
  strings:
    $key_f43d = { a3 4f [2] 91 6d [2] 97 58 [2] b9 58 [2] 86 44 }

  condition:
    any of them
}