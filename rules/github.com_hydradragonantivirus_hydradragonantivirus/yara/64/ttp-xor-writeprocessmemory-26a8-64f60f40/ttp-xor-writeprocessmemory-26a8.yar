rule TTP_XOR_WriteProcessMemory_26a8 {
  strings:
    $key_26a8 = { 71 da [2] 43 f8 [2] 45 cd [2] 6b cd [2] 54 d1 }

  condition:
    any of them
}