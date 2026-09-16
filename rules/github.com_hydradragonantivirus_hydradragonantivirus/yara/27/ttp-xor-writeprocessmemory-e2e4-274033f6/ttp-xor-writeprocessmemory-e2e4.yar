rule TTP_XOR_WriteProcessMemory_e2e4 {
  strings:
    $key_e2e4 = { b5 96 [2] 87 b4 [2] 81 81 [2] af 81 [2] 90 9d }

  condition:
    any of them
}