rule TTP_XOR_WriteProcessMemory_d30d {
  strings:
    $key_d30d = { 84 7f [2] b6 5d [2] b0 68 [2] 9e 68 [2] a1 74 }

  condition:
    any of them
}