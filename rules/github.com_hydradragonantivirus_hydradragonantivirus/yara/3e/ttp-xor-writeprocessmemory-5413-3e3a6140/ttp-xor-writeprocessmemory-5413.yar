rule TTP_XOR_WriteProcessMemory_5413 {
  strings:
    $key_5413 = { 03 61 [2] 31 43 [2] 37 76 [2] 19 76 [2] 26 6a }

  condition:
    any of them
}