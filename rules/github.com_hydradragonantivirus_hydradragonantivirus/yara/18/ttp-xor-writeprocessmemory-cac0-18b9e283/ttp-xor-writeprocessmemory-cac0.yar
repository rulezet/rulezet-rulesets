rule TTP_XOR_WriteProcessMemory_cac0 {
  strings:
    $key_cac0 = { 9d b2 [2] af 90 [2] a9 a5 [2] 87 a5 [2] b8 b9 }

  condition:
    any of them
}