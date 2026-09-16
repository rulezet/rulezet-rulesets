rule TTP_XOR_WriteProcessMemory_6807 {
  strings:
    $key_6807 = { 3f 75 [2] 0d 57 [2] 0b 62 [2] 25 62 [2] 1a 7e }

  condition:
    any of them
}