rule TTP_XOR_WriteProcessMemory_e614 {
  strings:
    $key_e614 = { b1 66 [2] 83 44 [2] 85 71 [2] ab 71 [2] 94 6d }

  condition:
    any of them
}