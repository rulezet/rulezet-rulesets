rule TTP_XOR_WriteProcessMemory_6a11 {
  strings:
    $key_6a11 = { 3d 63 [2] 0f 41 [2] 09 74 [2] 27 74 [2] 18 68 }

  condition:
    any of them
}