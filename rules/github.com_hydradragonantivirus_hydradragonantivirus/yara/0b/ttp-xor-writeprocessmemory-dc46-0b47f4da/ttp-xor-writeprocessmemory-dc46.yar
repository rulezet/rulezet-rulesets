rule TTP_XOR_WriteProcessMemory_dc46 {
  strings:
    $key_dc46 = { 8b 34 [2] b9 16 [2] bf 23 [2] 91 23 [2] ae 3f }

  condition:
    any of them
}