rule TTP_XOR_WriteProcessMemory_e644 {
  strings:
    $key_e644 = { b1 36 [2] 83 14 [2] 85 21 [2] ab 21 [2] 94 3d }

  condition:
    any of them
}