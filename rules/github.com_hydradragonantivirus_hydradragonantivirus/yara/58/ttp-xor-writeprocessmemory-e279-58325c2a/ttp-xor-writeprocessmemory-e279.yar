rule TTP_XOR_WriteProcessMemory_e279 {
  strings:
    $key_e279 = { b5 0b [2] 87 29 [2] 81 1c [2] af 1c [2] 90 00 }

  condition:
    any of them
}