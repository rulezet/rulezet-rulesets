rule TTP_XOR_WriteProcessMemory_e244 {
  strings:
    $key_e244 = { b5 36 [2] 87 14 [2] 81 21 [2] af 21 [2] 90 3d }

  condition:
    any of them
}