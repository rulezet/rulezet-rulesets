rule TTP_XOR_WriteProcessMemory_4b11 {
  strings:
    $key_4b11 = { 1c 63 [2] 2e 41 [2] 28 74 [2] 06 74 [2] 39 68 }

  condition:
    any of them
}