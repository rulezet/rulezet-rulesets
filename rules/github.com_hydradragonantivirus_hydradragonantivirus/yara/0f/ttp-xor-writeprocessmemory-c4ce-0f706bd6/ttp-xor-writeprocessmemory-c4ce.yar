rule TTP_XOR_WriteProcessMemory_c4ce {
  strings:
    $key_c4ce = { 93 bc [2] a1 9e [2] a7 ab [2] 89 ab [2] b6 b7 }

  condition:
    any of them
}