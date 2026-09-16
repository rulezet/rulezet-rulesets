rule TTP_XOR_WriteProcessMemory_5fce {
  strings:
    $key_5fce = { 08 bc [2] 3a 9e [2] 3c ab [2] 12 ab [2] 2d b7 }

  condition:
    any of them
}