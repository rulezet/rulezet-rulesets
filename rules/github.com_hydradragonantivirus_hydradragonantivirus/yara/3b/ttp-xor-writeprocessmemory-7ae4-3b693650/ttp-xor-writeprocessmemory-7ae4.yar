rule TTP_XOR_WriteProcessMemory_7ae4 {
  strings:
    $key_7ae4 = { 2d 96 [2] 1f b4 [2] 19 81 [2] 37 81 [2] 08 9d }

  condition:
    any of them
}