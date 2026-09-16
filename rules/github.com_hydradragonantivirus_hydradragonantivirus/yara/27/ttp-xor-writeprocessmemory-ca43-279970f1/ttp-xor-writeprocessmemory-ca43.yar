rule TTP_XOR_WriteProcessMemory_ca43 {
  strings:
    $key_ca43 = { 9d 31 [2] af 13 [2] a9 26 [2] 87 26 [2] b8 3a }

  condition:
    any of them
}