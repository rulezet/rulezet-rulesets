rule TTP_XOR_WriteProcessMemory_0661 {
  strings:
    $key_0661 = { 51 13 [2] 63 31 [2] 65 04 [2] 4b 04 [2] 74 18 }

  condition:
    any of them
}