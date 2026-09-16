rule TTP_XOR_WriteProcessMemory_66ae {
  strings:
    $key_66ae = { 31 dc [2] 03 fe [2] 05 cb [2] 2b cb [2] 14 d7 }

  condition:
    any of them
}