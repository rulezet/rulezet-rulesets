rule TTP_XOR_WriteProcessMemory_6074 {
  strings:
    $key_6074 = { 37 06 [2] 05 24 [2] 03 11 [2] 2d 11 [2] 12 0d }

  condition:
    any of them
}