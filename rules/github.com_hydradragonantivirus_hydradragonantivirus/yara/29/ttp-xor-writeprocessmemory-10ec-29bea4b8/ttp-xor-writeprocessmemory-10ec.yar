rule TTP_XOR_WriteProcessMemory_10ec {
  strings:
    $key_10ec = { 47 9e [2] 75 bc [2] 73 89 [2] 5d 89 [2] 62 95 }

  condition:
    any of them
}