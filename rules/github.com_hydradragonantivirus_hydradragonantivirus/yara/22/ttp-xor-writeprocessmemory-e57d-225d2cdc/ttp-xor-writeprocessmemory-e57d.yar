rule TTP_XOR_WriteProcessMemory_e57d {
  strings:
    $key_e57d = { b2 0f [2] 80 2d [2] 86 18 [2] a8 18 [2] 97 04 }

  condition:
    any of them
}