rule TTP_XOR_WriteProcessMemory_c133 {
  strings:
    $key_c133 = { 96 41 [2] a4 63 [2] a2 56 [2] 8c 56 [2] b3 4a }

  condition:
    any of them
}