rule TTP_XOR_WriteProcessMemory_0b31 {
  strings:
    $key_0b31 = { 5c 43 [2] 6e 61 [2] 68 54 [2] 46 54 [2] 79 48 }

  condition:
    any of them
}