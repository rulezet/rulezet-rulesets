rule TTP_XOR_WriteProcessMemory_5874 {
  strings:
    $key_5874 = { 0f 06 [2] 3d 24 [2] 3b 11 [2] 15 11 [2] 2a 0d }

  condition:
    any of them
}