rule TTP_XOR_WriteProcessMemory_efce {
  strings:
    $key_efce = { b8 bc [2] 8a 9e [2] 8c ab [2] a2 ab [2] 9d b7 }

  condition:
    any of them
}