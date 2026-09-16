rule TTP_XOR_WriteProcessMemory_e260 {
  strings:
    $key_e260 = { b5 12 [2] 87 30 [2] 81 05 [2] af 05 [2] 90 19 }

  condition:
    any of them
}