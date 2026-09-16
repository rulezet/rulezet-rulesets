rule TTP_XOR_WriteProcessMemory_0a32 {
  strings:
    $key_0a32 = { 5d 40 [2] 6f 62 [2] 69 57 [2] 47 57 [2] 78 4b }

  condition:
    any of them
}