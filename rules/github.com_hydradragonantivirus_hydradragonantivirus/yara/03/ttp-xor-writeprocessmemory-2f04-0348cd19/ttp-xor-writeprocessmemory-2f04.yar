rule TTP_XOR_WriteProcessMemory_2f04 {
  strings:
    $key_2f04 = { 78 76 [2] 4a 54 [2] 4c 61 [2] 62 61 [2] 5d 7d }

  condition:
    any of them
}