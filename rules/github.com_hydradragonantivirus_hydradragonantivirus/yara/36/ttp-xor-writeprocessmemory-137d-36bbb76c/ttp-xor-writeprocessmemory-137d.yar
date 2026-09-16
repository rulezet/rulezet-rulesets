rule TTP_XOR_WriteProcessMemory_137d {
  strings:
    $key_137d = { 44 0f [2] 76 2d [2] 70 18 [2] 5e 18 [2] 61 04 }

  condition:
    any of them
}