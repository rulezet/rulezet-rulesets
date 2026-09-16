rule TTP_XOR_WriteProcessMemory_6a03 {
  strings:
    $key_6a03 = { 3d 71 [2] 0f 53 [2] 09 66 [2] 27 66 [2] 18 7a }

  condition:
    any of them
}