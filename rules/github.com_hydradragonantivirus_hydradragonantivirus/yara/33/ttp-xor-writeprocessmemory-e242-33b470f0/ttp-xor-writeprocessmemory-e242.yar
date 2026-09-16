rule TTP_XOR_WriteProcessMemory_e242 {
  strings:
    $key_e242 = { b5 30 [2] 87 12 [2] 81 27 [2] af 27 [2] 90 3b }

  condition:
    any of them
}