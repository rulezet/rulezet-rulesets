rule TTP_XOR_WriteProcessMemory_c51f {
  strings:
    $key_c51f = { 92 6d [2] a0 4f [2] a6 7a [2] 88 7a [2] b7 66 }

  condition:
    any of them
}