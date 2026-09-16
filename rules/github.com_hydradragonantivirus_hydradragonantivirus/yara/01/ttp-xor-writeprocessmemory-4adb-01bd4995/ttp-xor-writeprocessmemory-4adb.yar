rule TTP_XOR_WriteProcessMemory_4adb {
  strings:
    $key_4adb = { 1d a9 [2] 2f 8b [2] 29 be [2] 07 be [2] 38 a2 }

  condition:
    any of them
}