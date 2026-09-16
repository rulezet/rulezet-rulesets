rule TTP_XOR_WriteProcessMemory_ca76 {
  strings:
    $key_ca76 = { 9d 04 [2] af 26 [2] a9 13 [2] 87 13 [2] b8 0f }

  condition:
    any of them
}