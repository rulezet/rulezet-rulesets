rule TTP_XOR_WriteProcessMemory_d42d {
  strings:
    $key_d42d = { 83 5f [2] b1 7d [2] b7 48 [2] 99 48 [2] a6 54 }

  condition:
    any of them
}