rule TTP_XOR_WriteProcessMemory_d35f {
  strings:
    $key_d35f = { 84 2d [2] b6 0f [2] b0 3a [2] 9e 3a [2] a1 26 }

  condition:
    any of them
}