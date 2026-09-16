rule TTP_XOR_WriteProcessMemory_38a8 {
  strings:
    $key_38a8 = { 6f da [2] 5d f8 [2] 5b cd [2] 75 cd [2] 4a d1 }

  condition:
    any of them
}