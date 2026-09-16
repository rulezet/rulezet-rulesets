rule TTP_XOR_WriteProcessMemory_0b33 {
  strings:
    $key_0b33 = { 5c 41 [2] 6e 63 [2] 68 56 [2] 46 56 [2] 79 4a }

  condition:
    any of them
}