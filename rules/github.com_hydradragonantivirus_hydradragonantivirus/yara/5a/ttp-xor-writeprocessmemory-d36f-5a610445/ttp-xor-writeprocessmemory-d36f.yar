rule TTP_XOR_WriteProcessMemory_d36f {
  strings:
    $key_d36f = { 84 1d [2] b6 3f [2] b0 0a [2] 9e 0a [2] a1 16 }

  condition:
    any of them
}