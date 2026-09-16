rule TTP_XOR_WriteProcessMemory_dc90 {
  strings:
    $key_dc90 = { 8b e2 [2] b9 c0 [2] bf f5 [2] 91 f5 [2] ae e9 }

  condition:
    any of them
}