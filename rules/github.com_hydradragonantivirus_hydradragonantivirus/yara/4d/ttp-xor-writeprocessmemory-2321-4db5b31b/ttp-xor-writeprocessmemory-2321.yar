rule TTP_XOR_WriteProcessMemory_2321 {
  strings:
    $key_2321 = { 74 53 [2] 46 71 [2] 40 44 [2] 6e 44 [2] 51 58 }

  condition:
    any of them
}