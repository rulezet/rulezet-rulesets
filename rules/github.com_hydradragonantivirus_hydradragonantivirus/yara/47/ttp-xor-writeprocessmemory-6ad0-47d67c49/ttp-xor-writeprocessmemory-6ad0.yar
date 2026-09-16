rule TTP_XOR_WriteProcessMemory_6ad0 {
  strings:
    $key_6ad0 = { 3d a2 [2] 0f 80 [2] 09 b5 [2] 27 b5 [2] 18 a9 }

  condition:
    any of them
}