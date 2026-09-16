rule TTP_XOR_WriteProcessMemory_6a32 {
  strings:
    $key_6a32 = { 3d 40 [2] 0f 62 [2] 09 57 [2] 27 57 [2] 18 4b }

  condition:
    any of them
}