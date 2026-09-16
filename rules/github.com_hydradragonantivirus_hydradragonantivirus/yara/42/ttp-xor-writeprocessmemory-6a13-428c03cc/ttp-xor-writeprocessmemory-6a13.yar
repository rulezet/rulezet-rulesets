rule TTP_XOR_WriteProcessMemory_6a13 {
  strings:
    $key_6a13 = { 3d 61 [2] 0f 43 [2] 09 76 [2] 27 76 [2] 18 6a }

  condition:
    any of them
}