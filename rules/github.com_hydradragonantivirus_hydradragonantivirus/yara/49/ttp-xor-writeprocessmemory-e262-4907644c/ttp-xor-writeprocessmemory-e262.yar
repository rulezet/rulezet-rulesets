rule TTP_XOR_WriteProcessMemory_e262 {
  strings:
    $key_e262 = { b5 10 [2] 87 32 [2] 81 07 [2] af 07 [2] 90 1b }

  condition:
    any of them
}