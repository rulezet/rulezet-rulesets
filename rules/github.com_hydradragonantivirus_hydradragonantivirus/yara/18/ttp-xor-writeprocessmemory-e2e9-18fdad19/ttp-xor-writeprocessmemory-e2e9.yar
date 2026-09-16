rule TTP_XOR_WriteProcessMemory_e2e9 {
  strings:
    $key_e2e9 = { b5 9b [2] 87 b9 [2] 81 8c [2] af 8c [2] 90 90 }

  condition:
    any of them
}