rule TTP_XOR_WriteProcessMemory_4837 {
  strings:
    $key_4837 = { 1f 45 [2] 2d 67 [2] 2b 52 [2] 05 52 [2] 3a 4e }

  condition:
    any of them
}