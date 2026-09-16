rule TTP_XOR_WriteProcessMemory_04a8 {
  strings:
    $key_04a8 = { 53 da [2] 61 f8 [2] 67 cd [2] 49 cd [2] 76 d1 }

  condition:
    any of them
}