rule TTP_XOR_WriteProcessMemory_7ad2 {
  strings:
    $key_7ad2 = { 2d a0 [2] 1f 82 [2] 19 b7 [2] 37 b7 [2] 08 ab }

  condition:
    any of them
}