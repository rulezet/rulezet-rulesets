rule TTP_XOR_WriteProcessMemory_60af {
  strings:
    $key_60af = { 37 dd [2] 05 ff [2] 03 ca [2] 2d ca [2] 12 d6 }

  condition:
    any of them
}