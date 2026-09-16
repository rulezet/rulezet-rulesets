rule TTP_XOR_WriteProcessMemory_6a37 {
  strings:
    $key_6a37 = { 3d 45 [2] 0f 67 [2] 09 52 [2] 27 52 [2] 18 4e }

  condition:
    any of them
}