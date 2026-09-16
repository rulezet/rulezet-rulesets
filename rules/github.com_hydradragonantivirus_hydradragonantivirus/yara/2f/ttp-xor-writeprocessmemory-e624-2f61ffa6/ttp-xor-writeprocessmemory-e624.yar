rule TTP_XOR_WriteProcessMemory_e624 {
  strings:
    $key_e624 = { b1 56 [2] 83 74 [2] 85 41 [2] ab 41 [2] 94 5d }

  condition:
    any of them
}