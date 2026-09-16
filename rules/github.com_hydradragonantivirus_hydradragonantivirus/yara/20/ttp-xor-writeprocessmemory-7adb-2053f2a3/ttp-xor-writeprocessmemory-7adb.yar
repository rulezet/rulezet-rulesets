rule TTP_XOR_WriteProcessMemory_7adb {
  strings:
    $key_7adb = { 2d a9 [2] 1f 8b [2] 19 be [2] 37 be [2] 08 a2 }

  condition:
    any of them
}