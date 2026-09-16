rule TTP_XOR_WriteProcessMemory_ca22 {
  strings:
    $key_ca22 = { 9d 50 [2] af 72 [2] a9 47 [2] 87 47 [2] b8 5b }

  condition:
    any of them
}