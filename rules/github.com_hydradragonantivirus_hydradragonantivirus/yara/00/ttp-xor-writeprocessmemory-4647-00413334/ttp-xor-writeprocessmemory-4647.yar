rule TTP_XOR_WriteProcessMemory_4647 {
  strings:
    $key_4647 = { 11 35 [2] 23 17 [2] 25 22 [2] 0b 22 [2] 34 3e }

  condition:
    any of them
}