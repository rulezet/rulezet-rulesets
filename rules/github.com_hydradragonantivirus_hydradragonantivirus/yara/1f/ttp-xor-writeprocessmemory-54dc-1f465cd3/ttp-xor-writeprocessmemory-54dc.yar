rule TTP_XOR_WriteProcessMemory_54dc {
  strings:
    $key_54dc = { 03 ae [2] 31 8c [2] 37 b9 [2] 19 b9 [2] 26 a5 }

  condition:
    any of them
}