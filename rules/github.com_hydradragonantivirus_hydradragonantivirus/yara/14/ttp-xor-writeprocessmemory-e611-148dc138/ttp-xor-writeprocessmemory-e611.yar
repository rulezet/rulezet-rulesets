rule TTP_XOR_WriteProcessMemory_e611 {
  strings:
    $key_e611 = { b1 63 [2] 83 41 [2] 85 74 [2] ab 74 [2] 94 68 }

  condition:
    any of them
}