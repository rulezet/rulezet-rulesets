rule TTP_XOR_WriteProcessMemory_dc36 {
  strings:
    $key_dc36 = { 8b 44 [2] b9 66 [2] bf 53 [2] 91 53 [2] ae 4f }

  condition:
    any of them
}