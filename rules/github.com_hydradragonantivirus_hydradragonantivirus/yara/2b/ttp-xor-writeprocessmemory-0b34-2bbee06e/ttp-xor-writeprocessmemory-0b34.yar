rule TTP_XOR_WriteProcessMemory_0b34 {
  strings:
    $key_0b34 = { 5c 46 [2] 6e 64 [2] 68 51 [2] 46 51 [2] 79 4d }

  condition:
    any of them
}