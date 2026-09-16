rule TTP_XOR_WriteProcessMemory_e080 {
  strings:
    $key_e080 = { b7 f2 [2] 85 d0 [2] 83 e5 [2] ad e5 [2] 92 f9 }

  condition:
    any of them
}