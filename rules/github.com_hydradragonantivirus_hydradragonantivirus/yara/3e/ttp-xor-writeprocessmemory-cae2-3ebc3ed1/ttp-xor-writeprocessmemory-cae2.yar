rule TTP_XOR_WriteProcessMemory_cae2 {
  strings:
    $key_cae2 = { 9d 90 [2] af b2 [2] a9 87 [2] 87 87 [2] b8 9b }

  condition:
    any of them
}