rule TTP_XOR_WriteProcessMemory_6b23 {
  strings:
    $key_6b23 = { 3c 51 [2] 0e 73 [2] 08 46 [2] 26 46 [2] 19 5a }

  condition:
    any of them
}