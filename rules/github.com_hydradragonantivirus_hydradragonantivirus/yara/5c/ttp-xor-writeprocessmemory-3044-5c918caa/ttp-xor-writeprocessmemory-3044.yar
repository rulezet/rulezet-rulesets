rule TTP_XOR_WriteProcessMemory_3044 {
  strings:
    $key_3044 = { 67 36 [2] 55 14 [2] 53 21 [2] 7d 21 [2] 42 3d }

  condition:
    any of them
}