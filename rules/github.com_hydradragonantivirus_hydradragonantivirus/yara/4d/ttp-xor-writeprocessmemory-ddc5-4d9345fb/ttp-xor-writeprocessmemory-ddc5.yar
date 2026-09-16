rule TTP_XOR_WriteProcessMemory_ddc5 {
  strings:
    $key_ddc5 = { 8a b7 [2] b8 95 [2] be a0 [2] 90 a0 [2] af bc }

  condition:
    any of them
}