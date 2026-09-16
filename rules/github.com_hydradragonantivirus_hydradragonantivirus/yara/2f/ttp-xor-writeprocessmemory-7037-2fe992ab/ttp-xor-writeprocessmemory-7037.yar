rule TTP_XOR_WriteProcessMemory_7037 {
  strings:
    $key_7037 = { 27 45 [2] 15 67 [2] 13 52 [2] 3d 52 [2] 02 4e }

  condition:
    any of them
}