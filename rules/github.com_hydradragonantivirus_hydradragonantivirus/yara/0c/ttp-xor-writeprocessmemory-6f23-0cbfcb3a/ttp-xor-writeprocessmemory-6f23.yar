rule TTP_XOR_WriteProcessMemory_6f23 {
  strings:
    $key_6f23 = { 38 51 [2] 0a 73 [2] 0c 46 [2] 22 46 [2] 1d 5a }

  condition:
    any of them
}