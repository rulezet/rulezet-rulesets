rule TTP_XOR_WriteProcessMemory_c121 {
  strings:
    $key_c121 = { 96 53 [2] a4 71 [2] a2 44 [2] 8c 44 [2] b3 58 }

  condition:
    any of them
}