rule TTP_XOR_WriteProcessMemory_1ea3 {
  strings:
    $key_1ea3 = { 49 d1 [2] 7b f3 [2] 7d c6 [2] 53 c6 [2] 6c da }

  condition:
    any of them
}