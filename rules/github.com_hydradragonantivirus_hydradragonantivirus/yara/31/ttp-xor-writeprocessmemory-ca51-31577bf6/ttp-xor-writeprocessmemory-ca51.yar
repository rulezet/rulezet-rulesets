rule TTP_XOR_WriteProcessMemory_ca51 {
  strings:
    $key_ca51 = { 9d 23 [2] af 01 [2] a9 34 [2] 87 34 [2] b8 28 }

  condition:
    any of them
}