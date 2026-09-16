rule TTP_XOR_WriteProcessMemory_d13f {
  strings:
    $key_d13f = { 86 4d [2] b4 6f [2] b2 5a [2] 9c 5a [2] a3 46 }

  condition:
    any of them
}