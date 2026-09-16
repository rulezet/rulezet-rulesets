rule TTP_XOR_WriteProcessMemory_7a32 {
  strings:
    $key_7a32 = { 2d 40 [2] 1f 62 [2] 19 57 [2] 37 57 [2] 08 4b }

  condition:
    any of them
}