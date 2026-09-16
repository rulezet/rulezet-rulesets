rule TTP_XOR_WriteProcessMemory_6fce {
  strings:
    $key_6fce = { 38 bc [2] 0a 9e [2] 0c ab [2] 22 ab [2] 1d b7 }

  condition:
    any of them
}