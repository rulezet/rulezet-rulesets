rule TTP_XOR_WriteProcessMemory_5c24 {
  strings:
    $key_5c24 = { 0b 56 [2] 39 74 [2] 3f 41 [2] 11 41 [2] 2e 5d }

  condition:
    any of them
}