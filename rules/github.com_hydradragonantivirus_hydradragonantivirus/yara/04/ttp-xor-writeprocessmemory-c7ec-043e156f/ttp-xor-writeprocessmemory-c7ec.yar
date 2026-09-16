rule TTP_XOR_WriteProcessMemory_c7ec {
  strings:
    $key_c7ec = { 90 9e [2] a2 bc [2] a4 89 [2] 8a 89 [2] b5 95 }

  condition:
    any of them
}