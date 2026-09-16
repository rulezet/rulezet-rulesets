rule TTP_XOR_WriteProcessMemory_d55f {
  strings:
    $key_d55f = { 82 2d [2] b0 0f [2] b6 3a [2] 98 3a [2] a7 26 }

  condition:
    any of them
}