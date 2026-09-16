rule TTP_XOR_WriteProcessMemory_adb1 {
  strings:
    $key_adb1 = { fa c3 [2] c8 e1 [2] ce d4 [2] e0 d4 [2] df c8 }

  condition:
    any of them
}