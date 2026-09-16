rule TTP_XOR_WriteProcessMemory_dc66 {
  strings:
    $key_dc66 = { 8b 14 [2] b9 36 [2] bf 03 [2] 91 03 [2] ae 1f }

  condition:
    any of them
}