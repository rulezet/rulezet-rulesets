rule TTP_XOR_WriteProcessMemory_dc14 {
  strings:
    $key_dc14 = { 8b 66 [2] b9 44 [2] bf 71 [2] 91 71 [2] ae 6d }

  condition:
    any of them
}