rule TTP_XOR_WriteProcessMemory_6834 {
  strings:
    $key_6834 = { 3f 46 [2] 0d 64 [2] 0b 51 [2] 25 51 [2] 1a 4d }

  condition:
    any of them
}