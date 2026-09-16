rule TTP_XOR_WriteProcessMemory_c8ec {
  strings:
    $key_c8ec = { 9f 9e [2] ad bc [2] ab 89 [2] 85 89 [2] ba 95 }

  condition:
    any of them
}