rule TTP_XOR_WriteProcessMemory_0b24 {
  strings:
    $key_0b24 = { 5c 56 [2] 6e 74 [2] 68 41 [2] 46 41 [2] 79 5d }

  condition:
    any of them
}