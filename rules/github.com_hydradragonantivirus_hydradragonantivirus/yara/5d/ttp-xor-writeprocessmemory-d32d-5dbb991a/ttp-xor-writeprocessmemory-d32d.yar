rule TTP_XOR_WriteProcessMemory_d32d {
  strings:
    $key_d32d = { 84 5f [2] b6 7d [2] b0 48 [2] 9e 48 [2] a1 54 }

  condition:
    any of them
}