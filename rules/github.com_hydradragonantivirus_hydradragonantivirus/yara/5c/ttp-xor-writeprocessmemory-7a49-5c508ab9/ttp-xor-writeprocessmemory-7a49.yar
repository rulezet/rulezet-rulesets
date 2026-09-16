rule TTP_XOR_WriteProcessMemory_7a49 {
  strings:
    $key_7a49 = { 2d 3b [2] 1f 19 [2] 19 2c [2] 37 2c [2] 08 30 }

  condition:
    any of them
}