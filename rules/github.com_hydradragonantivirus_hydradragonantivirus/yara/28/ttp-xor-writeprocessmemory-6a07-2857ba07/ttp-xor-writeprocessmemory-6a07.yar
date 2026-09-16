rule TTP_XOR_WriteProcessMemory_6a07 {
  strings:
    $key_6a07 = { 3d 75 [2] 0f 57 [2] 09 62 [2] 27 62 [2] 18 7e }

  condition:
    any of them
}