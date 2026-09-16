rule TTP_XOR_WriteProcessMemory_68a8 {
  strings:
    $key_68a8 = { 3f da [2] 0d f8 [2] 0b cd [2] 25 cd [2] 1a d1 }

  condition:
    any of them
}