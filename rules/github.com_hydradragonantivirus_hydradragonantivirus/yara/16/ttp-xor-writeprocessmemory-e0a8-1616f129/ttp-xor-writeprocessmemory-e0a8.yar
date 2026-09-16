rule TTP_XOR_WriteProcessMemory_e0a8 {
  strings:
    $key_e0a8 = { b7 da [2] 85 f8 [2] 83 cd [2] ad cd [2] 92 d1 }

  condition:
    any of them
}