rule TTP_XOR_WriteProcessMemory_6a49 {
  strings:
    $key_6a49 = { 3d 3b [2] 0f 19 [2] 09 2c [2] 27 2c [2] 18 30 }

  condition:
    any of them
}