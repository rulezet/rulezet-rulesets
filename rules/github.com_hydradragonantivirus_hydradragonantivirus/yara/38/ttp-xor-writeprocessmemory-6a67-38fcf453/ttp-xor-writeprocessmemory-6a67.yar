rule TTP_XOR_WriteProcessMemory_6a67 {
  strings:
    $key_6a67 = { 3d 15 [2] 0f 37 [2] 09 02 [2] 27 02 [2] 18 1e }

  condition:
    any of them
}