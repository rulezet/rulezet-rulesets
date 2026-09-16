rule TTP_XOR_WriteProcessMemory_e253 {
  strings:
    $key_e253 = { b5 21 [2] 87 03 [2] 81 36 [2] af 36 [2] 90 2a }

  condition:
    any of them
}