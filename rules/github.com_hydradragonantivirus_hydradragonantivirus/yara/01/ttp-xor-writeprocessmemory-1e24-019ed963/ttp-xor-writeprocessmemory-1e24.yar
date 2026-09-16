rule TTP_XOR_WriteProcessMemory_1e24 {
  strings:
    $key_1e24 = { 49 56 [2] 7b 74 [2] 7d 41 [2] 53 41 [2] 6c 5d }

  condition:
    any of them
}