rule TTP_XOR_WriteProcessMemory_3b23 {
  strings:
    $key_3b23 = { 6c 51 [2] 5e 73 [2] 58 46 [2] 76 46 [2] 49 5a }

  condition:
    any of them
}