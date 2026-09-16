rule TTP_XOR_WriteProcessMemory_7f23 {
  strings:
    $key_7f23 = { 28 51 [2] 1a 73 [2] 1c 46 [2] 32 46 [2] 0d 5a }

  condition:
    any of them
}