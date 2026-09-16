rule TTP_XOR_WriteProcessMemory_d35d {
  strings:
    $key_d35d = { 84 2f [2] b6 0d [2] b0 38 [2] 9e 38 [2] a1 24 }

  condition:
    any of them
}