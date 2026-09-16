rule TTP_XOR_WriteProcessMemory_f67d {
  strings:
    $key_f67d = { a1 0f [2] 93 2d [2] 95 18 [2] bb 18 [2] 84 04 }

  condition:
    any of them
}