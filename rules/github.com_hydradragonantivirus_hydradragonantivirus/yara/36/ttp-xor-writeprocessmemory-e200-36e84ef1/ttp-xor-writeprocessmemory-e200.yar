rule TTP_XOR_WriteProcessMemory_e200 {
  strings:
    $key_e200 = { b5 72 [2] 87 50 [2] 81 65 [2] af 65 [2] 90 79 }

  condition:
    any of them
}