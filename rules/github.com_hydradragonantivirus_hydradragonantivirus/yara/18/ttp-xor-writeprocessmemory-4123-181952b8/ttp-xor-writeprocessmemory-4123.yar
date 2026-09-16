rule TTP_XOR_WriteProcessMemory_4123 {
  strings:
    $key_4123 = { 16 51 [2] 24 73 [2] 22 46 [2] 0c 46 [2] 33 5a }

  condition:
    any of them
}