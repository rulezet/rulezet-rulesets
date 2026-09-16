rule TTP_XOR_WriteProcessMemory_e661 {
  strings:
    $key_e661 = { b1 13 [2] 83 31 [2] 85 04 [2] ab 04 [2] 94 18 }

  condition:
    any of them
}