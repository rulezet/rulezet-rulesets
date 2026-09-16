rule TTP_XOR_WriteProcessMemory_4274 {
  strings:
    $key_4274 = { 15 06 [2] 27 24 [2] 21 11 [2] 0f 11 [2] 30 0d }

  condition:
    any of them
}