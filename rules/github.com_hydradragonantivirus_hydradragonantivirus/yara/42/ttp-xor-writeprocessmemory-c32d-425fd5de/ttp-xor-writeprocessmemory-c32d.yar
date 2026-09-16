rule TTP_XOR_WriteProcessMemory_c32d {
  strings:
    $key_c32d = { 94 5f [2] a6 7d [2] a0 48 [2] 8e 48 [2] b1 54 }

  condition:
    any of them
}