rule TTP_XOR_WriteProcessMemory_6a04 {
  strings:
    $key_6a04 = { 3d 76 [2] 0f 54 [2] 09 61 [2] 27 61 [2] 18 7d }

  condition:
    any of them
}