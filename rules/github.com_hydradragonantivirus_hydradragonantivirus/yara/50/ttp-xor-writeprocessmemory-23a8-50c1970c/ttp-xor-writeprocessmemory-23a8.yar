rule TTP_XOR_WriteProcessMemory_23a8 {
  strings:
    $key_23a8 = { 74 da [2] 46 f8 [2] 40 cd [2] 6e cd [2] 51 d1 }

  condition:
    any of them
}