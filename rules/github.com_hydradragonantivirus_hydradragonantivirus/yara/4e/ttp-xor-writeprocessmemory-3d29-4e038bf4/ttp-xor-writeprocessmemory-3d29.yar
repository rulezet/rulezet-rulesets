rule TTP_XOR_WriteProcessMemory_3d29 {
  strings:
    $key_3d29 = { 6a 5b [2] 58 79 [2] 5e 4c [2] 70 4c [2] 4f 50 }

  condition:
    any of them
}