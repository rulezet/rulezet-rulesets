rule TTP_XOR_WriteProcessMemory_4f09 {
  strings:
    $key_4f09 = { 18 7b [2] 2a 59 [2] 2c 6c [2] 02 6c [2] 3d 70 }

  condition:
    any of them
}