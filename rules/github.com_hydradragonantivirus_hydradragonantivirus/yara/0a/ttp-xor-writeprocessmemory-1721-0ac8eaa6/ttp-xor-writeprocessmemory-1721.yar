rule TTP_XOR_WriteProcessMemory_1721 {
  strings:
    $key_1721 = { 40 53 [2] 72 71 [2] 74 44 [2] 5a 44 [2] 65 58 }

  condition:
    any of them
}