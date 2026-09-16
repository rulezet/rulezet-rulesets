rule TTP_XOR_WriteProcessMemory_dc72 {
  strings:
    $key_dc72 = { 8b 00 [2] b9 22 [2] bf 17 [2] 91 17 [2] ae 0b }

  condition:
    any of them
}