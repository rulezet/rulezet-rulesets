rule TTP_XOR_WriteProcessMemory_c15d {
  strings:
    $key_c15d = { 96 2f [2] a4 0d [2] a2 38 [2] 8c 38 [2] b3 24 }

  condition:
    any of them
}