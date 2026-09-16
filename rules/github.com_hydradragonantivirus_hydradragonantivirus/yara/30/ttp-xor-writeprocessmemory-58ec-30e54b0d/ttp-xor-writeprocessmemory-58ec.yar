rule TTP_XOR_WriteProcessMemory_58ec {
  strings:
    $key_58ec = { 0f 9e [2] 3d bc [2] 3b 89 [2] 15 89 [2] 2a 95 }

  condition:
    any of them
}