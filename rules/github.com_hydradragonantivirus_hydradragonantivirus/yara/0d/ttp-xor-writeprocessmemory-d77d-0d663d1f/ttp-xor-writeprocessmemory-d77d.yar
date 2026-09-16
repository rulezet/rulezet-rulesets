rule TTP_XOR_WriteProcessMemory_d77d {
  strings:
    $key_d77d = { 80 0f [2] b2 2d [2] b4 18 [2] 9a 18 [2] a5 04 }

  condition:
    any of them
}