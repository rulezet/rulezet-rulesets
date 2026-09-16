rule TTP_XOR_WriteProcessMemory_e084 {
  strings:
    $key_e084 = { b7 f6 [2] 85 d4 [2] 83 e1 [2] ad e1 [2] 92 fd }

  condition:
    any of them
}