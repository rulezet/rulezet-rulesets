rule TTP_XOR_WriteProcessMemory_28a8 {
  strings:
    $key_28a8 = { 7f da [2] 4d f8 [2] 4b cd [2] 65 cd [2] 5a d1 }

  condition:
    any of them
}