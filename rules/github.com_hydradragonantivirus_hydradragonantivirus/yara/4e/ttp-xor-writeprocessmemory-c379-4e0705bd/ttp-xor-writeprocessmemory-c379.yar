rule TTP_XOR_WriteProcessMemory_c379 {
  strings:
    $key_c379 = { 94 0b [2] a6 29 [2] a0 1c [2] 8e 1c [2] b1 00 }

  condition:
    any of them
}