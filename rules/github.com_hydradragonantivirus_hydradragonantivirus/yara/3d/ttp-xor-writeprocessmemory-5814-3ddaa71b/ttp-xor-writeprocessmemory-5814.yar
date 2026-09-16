rule TTP_XOR_WriteProcessMemory_5814 {
  strings:
    $key_5814 = { 0f 66 [2] 3d 44 [2] 3b 71 [2] 15 71 [2] 2a 6d }

  condition:
    any of them
}