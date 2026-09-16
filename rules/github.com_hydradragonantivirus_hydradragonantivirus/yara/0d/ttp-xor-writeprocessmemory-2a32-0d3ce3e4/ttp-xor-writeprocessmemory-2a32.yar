rule TTP_XOR_WriteProcessMemory_2a32 {
  strings:
    $key_2a32 = { 7d 40 [2] 4f 62 [2] 49 57 [2] 67 57 [2] 58 4b }

  condition:
    any of them
}