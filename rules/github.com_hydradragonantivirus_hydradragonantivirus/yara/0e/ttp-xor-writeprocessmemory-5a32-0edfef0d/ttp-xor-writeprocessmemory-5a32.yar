rule TTP_XOR_WriteProcessMemory_5a32 {
  strings:
    $key_5a32 = { 0d 40 [2] 3f 62 [2] 39 57 [2] 17 57 [2] 28 4b }

  condition:
    any of them
}