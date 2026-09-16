rule TTP_XOR_WriteProcessMemory_2fce {
  strings:
    $key_2fce = { 78 bc [2] 4a 9e [2] 4c ab [2] 62 ab [2] 5d b7 }

  condition:
    any of them
}