rule TTP_XOR_WriteProcessMemory_1ea5 {
  strings:
    $key_1ea5 = { 49 d7 [2] 7b f5 [2] 7d c0 [2] 53 c0 [2] 6c dc }

  condition:
    any of them
}