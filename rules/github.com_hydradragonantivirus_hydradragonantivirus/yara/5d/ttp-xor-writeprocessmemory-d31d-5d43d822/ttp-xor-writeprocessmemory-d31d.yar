rule TTP_XOR_WriteProcessMemory_d31d {
  strings:
    $key_d31d = { 84 6f [2] b6 4d [2] b0 78 [2] 9e 78 [2] a1 64 }

  condition:
    any of them
}