rule TTP_XOR_WriteProcessMemory_6a29 {
  strings:
    $key_6a29 = { 3d 5b [2] 0f 79 [2] 09 4c [2] 27 4c [2] 18 50 }

  condition:
    any of them
}