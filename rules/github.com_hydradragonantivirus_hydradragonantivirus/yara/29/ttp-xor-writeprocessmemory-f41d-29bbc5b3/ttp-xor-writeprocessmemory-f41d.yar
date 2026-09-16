rule TTP_XOR_WriteProcessMemory_f41d {
  strings:
    $key_f41d = { a3 6f [2] 91 4d [2] 97 78 [2] b9 78 [2] 86 64 }

  condition:
    any of them
}