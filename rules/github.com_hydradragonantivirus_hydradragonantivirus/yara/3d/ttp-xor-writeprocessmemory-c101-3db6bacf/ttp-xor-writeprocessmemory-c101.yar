rule TTP_XOR_WriteProcessMemory_c101 {
  strings:
    $key_c101 = { 96 73 [2] a4 51 [2] a2 64 [2] 8c 64 [2] b3 78 }

  condition:
    any of them
}