rule TTP_XOR_WriteProcessMemory_6a08 {
  strings:
    $key_6a08 = { 3d 7a [2] 0f 58 [2] 09 6d [2] 27 6d [2] 18 71 }

  condition:
    any of them
}