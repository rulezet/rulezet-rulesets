rule TTP_XOR_WriteProcessMemory_d601 {
  strings:
    $key_d601 = { 81 73 [2] b3 51 [2] b5 64 [2] 9b 64 [2] a4 78 }

  condition:
    any of them
}