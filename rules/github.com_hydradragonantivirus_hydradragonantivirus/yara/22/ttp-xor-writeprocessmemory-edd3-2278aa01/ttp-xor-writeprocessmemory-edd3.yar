rule TTP_XOR_WriteProcessMemory_edd3 {
  strings:
    $key_edd3 = { ba a1 [2] 88 83 [2] 8e b6 [2] a0 b6 [2] 9f aa }

  condition:
    any of them
}