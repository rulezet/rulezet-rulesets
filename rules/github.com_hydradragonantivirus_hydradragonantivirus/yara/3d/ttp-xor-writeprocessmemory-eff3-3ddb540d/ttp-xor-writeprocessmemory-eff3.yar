rule TTP_XOR_WriteProcessMemory_eff3 {
  strings:
    $key_eff3 = { b8 81 [2] 8a a3 [2] 8c 96 [2] a2 96 [2] 9d 8a }

  condition:
    any of them
}