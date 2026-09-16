rule TTP_XOR_WriteProcessMemory_f458 {
  strings:
    $key_f458 = { a3 2a [2] 91 08 [2] 97 3d [2] b9 3d [2] 86 21 }

  condition:
    any of them
}