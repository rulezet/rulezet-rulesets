rule TTP_XOR_WriteProcessMemory_6aac {
  strings:
    $key_6aac = { 3d de [2] 0f fc [2] 09 c9 [2] 27 c9 [2] 18 d5 }

  condition:
    any of them
}