rule TTP_XOR_WriteProcessMemory_90a8 {
  strings:
    $key_90a8 = { c7 da [2] f5 f8 [2] f3 cd [2] dd cd [2] e2 d1 }

  condition:
    any of them
}