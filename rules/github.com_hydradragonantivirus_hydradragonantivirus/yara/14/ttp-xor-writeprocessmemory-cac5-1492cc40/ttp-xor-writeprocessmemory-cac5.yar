rule TTP_XOR_WriteProcessMemory_cac5 {
  strings:
    $key_cac5 = { 9d b7 [2] af 95 [2] a9 a0 [2] 87 a0 [2] b8 bc }

  condition:
    any of them
}