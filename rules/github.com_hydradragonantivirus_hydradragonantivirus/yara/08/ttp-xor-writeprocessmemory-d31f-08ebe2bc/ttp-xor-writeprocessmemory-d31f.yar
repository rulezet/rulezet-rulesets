rule TTP_XOR_WriteProcessMemory_d31f {
  strings:
    $key_d31f = { 84 6d [2] b6 4f [2] b0 7a [2] 9e 7a [2] a1 66 }

  condition:
    any of them
}