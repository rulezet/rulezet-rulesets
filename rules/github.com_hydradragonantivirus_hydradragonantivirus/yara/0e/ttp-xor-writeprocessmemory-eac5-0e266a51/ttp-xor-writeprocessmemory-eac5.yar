rule TTP_XOR_WriteProcessMemory_eac5 {
  strings:
    $key_eac5 = { bd b7 [2] 8f 95 [2] 89 a0 [2] a7 a0 [2] 98 bc }

  condition:
    any of them
}