rule TTP_XOR_WriteProcessMemory_e086 {
  strings:
    $key_e086 = { b7 f4 [2] 85 d6 [2] 83 e3 [2] ad e3 [2] 92 ff }

  condition:
    any of them
}