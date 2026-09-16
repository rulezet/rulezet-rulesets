rule TTP_XOR_WriteProcessMemory_6a76 {
  strings:
    $key_6a76 = { 3d 04 [2] 0f 26 [2] 09 13 [2] 27 13 [2] 18 0f }

  condition:
    any of them
}