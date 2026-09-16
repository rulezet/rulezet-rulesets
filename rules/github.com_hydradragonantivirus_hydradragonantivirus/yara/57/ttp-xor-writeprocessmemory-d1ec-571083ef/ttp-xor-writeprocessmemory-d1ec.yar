rule TTP_XOR_WriteProcessMemory_d1ec {
  strings:
    $key_d1ec = { 86 9e [2] b4 bc [2] b2 89 [2] 9c 89 [2] a3 95 }

  condition:
    any of them
}