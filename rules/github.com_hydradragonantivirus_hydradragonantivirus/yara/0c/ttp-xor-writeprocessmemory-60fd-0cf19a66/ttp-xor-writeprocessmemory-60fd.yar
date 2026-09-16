rule TTP_XOR_WriteProcessMemory_60fd {
  strings:
    $key_60fd = { 37 8f [2] 05 ad [2] 03 98 [2] 2d 98 [2] 12 84 }

  condition:
    any of them
}