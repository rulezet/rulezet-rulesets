rule TTP_XOR_WriteProcessMemory_5807 {
  strings:
    $key_5807 = { 0f 75 [2] 3d 57 [2] 3b 62 [2] 15 62 [2] 2a 7e }

  condition:
    any of them
}