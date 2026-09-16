rule TTP_XOR_WriteProcessMemory_c67d {
  strings:
    $key_c67d = { 91 0f [2] a3 2d [2] a5 18 [2] 8b 18 [2] b4 04 }

  condition:
    any of them
}