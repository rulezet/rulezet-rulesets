rule TTP_XOR_WriteProcessMemory_0b03 {
  strings:
    $key_0b03 = { 5c 71 [2] 6e 53 [2] 68 66 [2] 46 66 [2] 79 7a }

  condition:
    any of them
}