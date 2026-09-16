rule TTP_XOR_WriteProcessMemory_00dc {
  strings:
    $key_00dc = { 57 ae [2] 65 8c [2] 63 b9 [2] 4d b9 [2] 72 a5 }

  condition:
    any of them
}