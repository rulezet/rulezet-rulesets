rule TTP_XOR_WriteProcessMemory_36ec {
  strings:
    $key_36ec = { 61 9e [2] 53 bc [2] 55 89 [2] 7b 89 [2] 44 95 }

  condition:
    any of them
}