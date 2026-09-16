rule TTP_XOR_WriteProcessMemory_d44a {
  strings:
    $key_d44a = { 83 38 [2] b1 1a [2] b7 2f [2] 99 2f [2] a6 33 }

  condition:
    any of them
}