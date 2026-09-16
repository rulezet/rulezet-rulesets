rule TTP_XOR_WriteProcessMemory_e653 {
  strings:
    $key_e653 = { b1 21 [2] 83 03 [2] 85 36 [2] ab 36 [2] 94 2a }

  condition:
    any of them
}