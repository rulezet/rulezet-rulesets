rule TTP_XOR_WriteProcessMemory_c111 {
  strings:
    $key_c111 = { 96 63 [2] a4 41 [2] a2 74 [2] 8c 74 [2] b3 68 }

  condition:
    any of them
}