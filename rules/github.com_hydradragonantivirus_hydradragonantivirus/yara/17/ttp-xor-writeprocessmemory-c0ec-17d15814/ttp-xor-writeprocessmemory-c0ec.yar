rule TTP_XOR_WriteProcessMemory_c0ec {
  strings:
    $key_c0ec = { 97 9e [2] a5 bc [2] a3 89 [2] 8d 89 [2] b2 95 }

  condition:
    any of them
}