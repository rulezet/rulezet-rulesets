rule TTP_XOR_WriteProcessMemory_02a8 {
  strings:
    $key_02a8 = { 55 da [2] 67 f8 [2] 61 cd [2] 4f cd [2] 70 d1 }

  condition:
    any of them
}