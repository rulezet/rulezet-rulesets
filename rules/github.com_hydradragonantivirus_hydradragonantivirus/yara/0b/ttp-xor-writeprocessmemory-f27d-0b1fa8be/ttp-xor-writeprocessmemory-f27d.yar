rule TTP_XOR_WriteProcessMemory_f27d {
  strings:
    $key_f27d = { a5 0f [2] 97 2d [2] 91 18 [2] bf 18 [2] 80 04 }

  condition:
    any of them
}