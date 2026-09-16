rule TTP_XOR_WriteProcessMemory_dc91 {
  strings:
    $key_dc91 = { 8b e3 [2] b9 c1 [2] bf f4 [2] 91 f4 [2] ae e8 }

  condition:
    any of them
}