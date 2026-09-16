rule TTP_XOR_WriteProcessMemory_e264 {
  strings:
    $key_e264 = { b5 16 [2] 87 34 [2] 81 01 [2] af 01 [2] 90 1d }

  condition:
    any of them
}