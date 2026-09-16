rule TTP_XOR_WriteProcessMemory_6adb {
  strings:
    $key_6adb = { 3d a9 [2] 0f 8b [2] 09 be [2] 27 be [2] 18 a2 }

  condition:
    any of them
}