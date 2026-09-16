rule TTP_XOR_WriteProcessMemory_3974 {
  strings:
    $key_3974 = { 6e 06 [2] 5c 24 [2] 5a 11 [2] 74 11 [2] 4b 0d }

  condition:
    any of them
}