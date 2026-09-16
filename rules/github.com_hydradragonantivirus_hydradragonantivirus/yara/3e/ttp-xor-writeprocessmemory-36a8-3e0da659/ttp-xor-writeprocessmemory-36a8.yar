rule TTP_XOR_WriteProcessMemory_36a8 {
  strings:
    $key_36a8 = { 61 da [2] 53 f8 [2] 55 cd [2] 7b cd [2] 44 d1 }

  condition:
    any of them
}