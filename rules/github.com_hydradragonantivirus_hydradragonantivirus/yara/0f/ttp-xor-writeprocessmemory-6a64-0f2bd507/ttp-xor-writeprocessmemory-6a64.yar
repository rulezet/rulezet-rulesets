rule TTP_XOR_WriteProcessMemory_6a64 {
  strings:
    $key_6a64 = { 3d 16 [2] 0f 34 [2] 09 01 [2] 27 01 [2] 18 1d }

  condition:
    any of them
}