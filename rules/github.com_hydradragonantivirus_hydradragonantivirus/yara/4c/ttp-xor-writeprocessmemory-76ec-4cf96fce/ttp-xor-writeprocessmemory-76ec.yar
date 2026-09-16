rule TTP_XOR_WriteProcessMemory_76ec {
  strings:
    $key_76ec = { 21 9e [2] 13 bc [2] 15 89 [2] 3b 89 [2] 04 95 }

  condition:
    any of them
}