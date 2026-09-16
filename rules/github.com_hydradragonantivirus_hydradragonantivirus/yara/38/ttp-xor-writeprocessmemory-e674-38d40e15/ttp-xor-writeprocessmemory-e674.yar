rule TTP_XOR_WriteProcessMemory_e674 {
  strings:
    $key_e674 = { b1 06 [2] 83 24 [2] 85 11 [2] ab 11 [2] 94 0d }

  condition:
    any of them
}