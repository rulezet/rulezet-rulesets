rule TTP_XOR_WriteProcessMemory_70ea {
  strings:
    $key_70ea = { 27 98 [2] 15 ba [2] 13 8f [2] 3d 8f [2] 02 93 }

  condition:
    any of them
}