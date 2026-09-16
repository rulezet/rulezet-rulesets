rule TTP_XOR_WriteProcessMemory_67a8 {
  strings:
    $key_67a8 = { 30 da [2] 02 f8 [2] 04 cd [2] 2a cd [2] 15 d1 }

  condition:
    any of them
}