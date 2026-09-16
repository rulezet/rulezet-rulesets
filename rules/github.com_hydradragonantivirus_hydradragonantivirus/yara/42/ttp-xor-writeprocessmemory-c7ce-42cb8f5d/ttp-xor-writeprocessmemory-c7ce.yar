rule TTP_XOR_WriteProcessMemory_c7ce {
  strings:
    $key_c7ce = { 90 bc [2] a2 9e [2] a4 ab [2] 8a ab [2] b5 b7 }

  condition:
    any of them
}