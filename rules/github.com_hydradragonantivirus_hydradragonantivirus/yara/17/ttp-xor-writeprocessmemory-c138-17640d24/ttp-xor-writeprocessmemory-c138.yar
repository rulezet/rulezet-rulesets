rule TTP_XOR_WriteProcessMemory_c138 {
  strings:
    $key_c138 = { 96 4a [2] a4 68 [2] a2 5d [2] 8c 5d [2] b3 41 }

  condition:
    any of them
}