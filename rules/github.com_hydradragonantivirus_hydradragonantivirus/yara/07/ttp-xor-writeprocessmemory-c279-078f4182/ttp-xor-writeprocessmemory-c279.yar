rule TTP_XOR_WriteProcessMemory_c279 {
  strings:
    $key_c279 = { 95 0b [2] a7 29 [2] a1 1c [2] 8f 1c [2] b0 00 }

  condition:
    any of them
}