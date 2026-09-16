rule TTP_XOR_WriteProcessMemory_d2ce {
  strings:
    $key_d2ce = { 85 bc [2] b7 9e [2] b1 ab [2] 9f ab [2] a0 b7 }

  condition:
    any of them
}