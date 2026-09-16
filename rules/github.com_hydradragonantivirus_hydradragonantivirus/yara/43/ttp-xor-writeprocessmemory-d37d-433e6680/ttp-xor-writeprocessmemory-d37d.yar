rule TTP_XOR_WriteProcessMemory_d37d {
  strings:
    $key_d37d = { 84 0f [2] b6 2d [2] b0 18 [2] 9e 18 [2] a1 04 }

  condition:
    any of them
}