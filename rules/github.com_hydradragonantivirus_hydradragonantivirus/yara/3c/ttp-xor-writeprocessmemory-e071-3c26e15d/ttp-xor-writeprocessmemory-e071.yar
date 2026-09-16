rule TTP_XOR_WriteProcessMemory_e071 {
  strings:
    $key_e071 = { b7 03 [2] 85 21 [2] 83 14 [2] ad 14 [2] 92 08 }

  condition:
    any of them
}