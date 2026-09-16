rule TTP_XOR_WriteProcessMemory_70ae {
  strings:
    $key_70ae = { 27 dc [2] 15 fe [2] 13 cb [2] 3d cb [2] 02 d7 }

  condition:
    any of them
}