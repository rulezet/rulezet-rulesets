rule TTP_XOR_WriteProcessMemory_e263 {
  strings:
    $key_e263 = { b5 11 [2] 87 33 [2] 81 06 [2] af 06 [2] 90 1a }

  condition:
    any of them
}