rule TTP_XOR_WriteProcessMemory_6c23 {
  strings:
    $key_6c23 = { 3b 51 [2] 09 73 [2] 0f 46 [2] 21 46 [2] 1e 5a }

  condition:
    any of them
}