rule TTP_XOR_WriteProcessMemory_c13f {
  strings:
    $key_c13f = { 96 4d [2] a4 6f [2] a2 5a [2] 8c 5a [2] b3 46 }

  condition:
    any of them
}