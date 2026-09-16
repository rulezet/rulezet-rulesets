rule TTP_XOR_WriteProcessMemory_66ec {
  strings:
    $key_66ec = { 31 9e [2] 03 bc [2] 05 89 [2] 2b 89 [2] 14 95 }

  condition:
    any of them
}