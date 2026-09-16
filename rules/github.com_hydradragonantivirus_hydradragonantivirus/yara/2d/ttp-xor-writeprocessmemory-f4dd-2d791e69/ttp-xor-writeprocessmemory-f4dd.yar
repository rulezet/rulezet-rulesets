rule TTP_XOR_WriteProcessMemory_f4dd {
  strings:
    $key_f4dd = { a3 af [2] 91 8d [2] 97 b8 [2] b9 b8 [2] 86 a4 }

  condition:
    any of them
}