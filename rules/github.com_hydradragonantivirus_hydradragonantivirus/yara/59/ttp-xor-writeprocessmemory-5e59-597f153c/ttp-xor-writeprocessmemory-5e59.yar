rule TTP_XOR_WriteProcessMemory_5e59 {
  strings:
    $key_5e59 = { 09 2b [2] 3b 09 [2] 3d 3c [2] 13 3c [2] 2c 20 }

  condition:
    any of them
}