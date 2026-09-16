rule TTP_XOR_WriteProcessMemory_3834 {
  strings:
    $key_3834 = { 6f 46 [2] 5d 64 [2] 5b 51 [2] 75 51 [2] 4a 4d }

  condition:
    any of them
}