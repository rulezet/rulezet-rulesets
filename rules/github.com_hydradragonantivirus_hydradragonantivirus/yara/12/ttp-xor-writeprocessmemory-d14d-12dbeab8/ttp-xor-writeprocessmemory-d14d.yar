rule TTP_XOR_WriteProcessMemory_d14d {
  strings:
    $key_d14d = { 86 3f [2] b4 1d [2] b2 28 [2] 9c 28 [2] a3 34 }

  condition:
    any of them
}