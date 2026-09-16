rule TTP_XOR_WriteProcessMemory_6647 {
  strings:
    $key_6647 = { 31 35 [2] 03 17 [2] 05 22 [2] 2b 22 [2] 14 3e }

  condition:
    any of them
}