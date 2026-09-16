rule TTP_XOR_WriteProcessMemory_adb9 {
  strings:
    $key_adb9 = { fa cb [2] c8 e9 [2] ce dc [2] e0 dc [2] df c0 }

  condition:
    any of them
}