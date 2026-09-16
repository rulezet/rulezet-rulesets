rule TTP_XOR_WriteProcessMemory_3fce {
  strings:
    $key_3fce = { 68 bc [2] 5a 9e [2] 5c ab [2] 72 ab [2] 4d b7 }

  condition:
    any of them
}