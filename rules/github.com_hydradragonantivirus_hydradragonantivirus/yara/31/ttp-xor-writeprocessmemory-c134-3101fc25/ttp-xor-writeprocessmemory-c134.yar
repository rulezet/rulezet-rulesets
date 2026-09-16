rule TTP_XOR_WriteProcessMemory_c134 {
  strings:
    $key_c134 = { 96 46 [2] a4 64 [2] a2 51 [2] 8c 51 [2] b3 4d }

  condition:
    any of them
}