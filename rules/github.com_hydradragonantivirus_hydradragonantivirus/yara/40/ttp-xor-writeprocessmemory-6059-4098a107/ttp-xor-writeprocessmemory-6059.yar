rule TTP_XOR_WriteProcessMemory_6059 {
  strings:
    $key_6059 = { 37 2b [2] 05 09 [2] 03 3c [2] 2d 3c [2] 12 20 }

  condition:
    any of them
}