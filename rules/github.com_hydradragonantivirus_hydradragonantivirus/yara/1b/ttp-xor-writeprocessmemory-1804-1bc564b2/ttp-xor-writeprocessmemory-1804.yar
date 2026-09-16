rule TTP_XOR_WriteProcessMemory_1804 {
  strings:
    $key_1804 = { 4f 76 [2] 7d 54 [2] 7b 61 [2] 55 61 [2] 6a 7d }

  condition:
    any of them
}