rule TTP_XOR_WriteProcessMemory_6a30 {
  strings:
    $key_6a30 = { 3d 42 [2] 0f 60 [2] 09 55 [2] 27 55 [2] 18 49 }

  condition:
    any of them
}