rule TTP_XOR_WriteProcessMemory_ca26 {
  strings:
    $key_ca26 = { 9d 54 [2] af 76 [2] a9 43 [2] 87 43 [2] b8 5f }

  condition:
    any of them
}