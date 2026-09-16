rule TTP_XOR_WriteProcessMemory_7ae7 {
  strings:
    $key_7ae7 = { 2d 95 [2] 1f b7 [2] 19 82 [2] 37 82 [2] 08 9e }

  condition:
    any of them
}