rule TTP_XOR_WriteProcessMemory_4b61 {
  strings:
    $key_4b61 = { 1c 13 [2] 2e 31 [2] 28 04 [2] 06 04 [2] 39 18 }

  condition:
    any of them
}