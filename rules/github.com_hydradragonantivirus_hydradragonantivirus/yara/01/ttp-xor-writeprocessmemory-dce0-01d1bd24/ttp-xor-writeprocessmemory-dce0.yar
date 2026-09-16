rule TTP_XOR_WriteProcessMemory_dce0 {
  strings:
    $key_dce0 = { 8b 92 [2] b9 b0 [2] bf 85 [2] 91 85 [2] ae 99 }

  condition:
    any of them
}