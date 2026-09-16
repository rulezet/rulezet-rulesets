rule TTP_XOR_WriteProcessMemory_dc64 {
  strings:
    $key_dc64 = { 8b 16 [2] b9 34 [2] bf 01 [2] 91 01 [2] ae 1d }

  condition:
    any of them
}