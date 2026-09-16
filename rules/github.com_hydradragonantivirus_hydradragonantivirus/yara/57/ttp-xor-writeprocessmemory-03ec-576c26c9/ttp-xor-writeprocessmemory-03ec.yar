rule TTP_XOR_WriteProcessMemory_03ec {
  strings:
    $key_03ec = { 54 9e [2] 66 bc [2] 60 89 [2] 4e 89 [2] 71 95 }

  condition:
    any of them
}