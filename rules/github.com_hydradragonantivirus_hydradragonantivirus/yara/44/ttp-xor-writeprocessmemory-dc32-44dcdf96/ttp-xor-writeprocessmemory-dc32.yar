rule TTP_XOR_WriteProcessMemory_dc32 {
  strings:
    $key_dc32 = { 8b 40 [2] b9 62 [2] bf 57 [2] 91 57 [2] ae 4b }

  condition:
    any of them
}