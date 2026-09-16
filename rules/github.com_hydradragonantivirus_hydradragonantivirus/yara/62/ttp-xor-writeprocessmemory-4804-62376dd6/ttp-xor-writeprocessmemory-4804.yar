rule TTP_XOR_WriteProcessMemory_4804 {
  strings:
    $key_4804 = { 1f 76 [2] 2d 54 [2] 2b 61 [2] 05 61 [2] 3a 7d }

  condition:
    any of them
}