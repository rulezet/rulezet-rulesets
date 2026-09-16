rule TTP_XOR_WriteProcessMemory_e731 {
  strings:
    $key_e731 = { b0 43 [2] 82 61 [2] 84 54 [2] aa 54 [2] 95 48 }

  condition:
    any of them
}