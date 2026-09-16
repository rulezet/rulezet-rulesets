rule TTP_XOR_WriteProcessMemory_e204 {
  strings:
    $key_e204 = { b5 76 [2] 87 54 [2] 81 61 [2] af 61 [2] 90 7d }

  condition:
    any of them
}