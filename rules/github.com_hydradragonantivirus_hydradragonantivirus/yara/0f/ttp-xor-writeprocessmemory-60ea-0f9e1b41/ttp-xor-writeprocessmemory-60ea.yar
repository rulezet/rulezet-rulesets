rule TTP_XOR_WriteProcessMemory_60ea {
  strings:
    $key_60ea = { 37 98 [2] 05 ba [2] 03 8f [2] 2d 8f [2] 12 93 }

  condition:
    any of them
}