rule TTP_XOR_WriteProcessMemory_6673 {
  strings:
    $key_6673 = { 31 01 [2] 03 23 [2] 05 16 [2] 2b 16 [2] 14 0a }

  condition:
    any of them
}