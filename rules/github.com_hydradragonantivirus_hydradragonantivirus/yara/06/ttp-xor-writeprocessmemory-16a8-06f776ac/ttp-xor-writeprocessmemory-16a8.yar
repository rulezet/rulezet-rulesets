rule TTP_XOR_WriteProcessMemory_16a8 {
  strings:
    $key_16a8 = { 41 da [2] 73 f8 [2] 75 cd [2] 5b cd [2] 64 d1 }

  condition:
    any of them
}