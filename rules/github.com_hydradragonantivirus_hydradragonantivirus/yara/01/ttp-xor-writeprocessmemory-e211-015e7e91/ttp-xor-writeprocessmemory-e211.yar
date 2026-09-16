rule TTP_XOR_WriteProcessMemory_e211 {
  strings:
    $key_e211 = { b5 63 [2] 87 41 [2] 81 74 [2] af 74 [2] 90 68 }

  condition:
    any of them
}