rule TTP_XOR_WriteProcessMemory_adb8 {
  strings:
    $key_adb8 = { fa ca [2] c8 e8 [2] ce dd [2] e0 dd [2] df c1 }

  condition:
    any of them
}