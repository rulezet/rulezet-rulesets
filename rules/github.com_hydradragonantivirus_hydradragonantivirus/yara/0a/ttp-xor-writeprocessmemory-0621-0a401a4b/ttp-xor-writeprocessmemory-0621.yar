rule TTP_XOR_WriteProcessMemory_0621 {
  strings:
    $key_0621 = { 51 53 [2] 63 71 [2] 65 44 [2] 4b 44 [2] 74 58 }

  condition:
    any of them
}