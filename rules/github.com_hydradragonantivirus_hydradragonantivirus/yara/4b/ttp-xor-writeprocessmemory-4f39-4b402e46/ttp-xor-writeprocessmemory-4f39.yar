rule TTP_XOR_WriteProcessMemory_4f39 {
  strings:
    $key_4f39 = { 18 4b [2] 2a 69 [2] 2c 5c [2] 02 5c [2] 3d 40 }

  condition:
    any of them
}