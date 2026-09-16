rule TTP_XOR_WriteProcessMemory_e613 {
  strings:
    $key_e613 = { b1 61 [2] 83 43 [2] 85 76 [2] ab 76 [2] 94 6a }

  condition:
    any of them
}