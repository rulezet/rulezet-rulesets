rule TTP_XOR_WriteProcessMemory_e9d5 {
  strings:
    $key_e9d5 = { be a7 [2] 8c 85 [2] 8a b0 [2] a4 b0 [2] 9b ac }

  condition:
    any of them
}