rule TTP_XOR_WriteProcessMemory_2344 {
  strings:
    $key_2344 = { 74 36 [2] 46 14 [2] 40 21 [2] 6e 21 [2] 51 3d }

  condition:
    any of them
}