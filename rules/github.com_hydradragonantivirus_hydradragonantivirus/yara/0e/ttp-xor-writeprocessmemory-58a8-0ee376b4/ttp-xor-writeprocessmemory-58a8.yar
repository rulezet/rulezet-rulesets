rule TTP_XOR_WriteProcessMemory_58a8 {
  strings:
    $key_58a8 = { 0f da [2] 3d f8 [2] 3b cd [2] 15 cd [2] 2a d1 }

  condition:
    any of them
}