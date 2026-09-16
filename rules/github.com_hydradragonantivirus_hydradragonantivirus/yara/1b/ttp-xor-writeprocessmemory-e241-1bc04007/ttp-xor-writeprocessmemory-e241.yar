rule TTP_XOR_WriteProcessMemory_e241 {
  strings:
    $key_e241 = { b5 33 [2] 87 11 [2] 81 24 [2] af 24 [2] 90 38 }

  condition:
    any of them
}