rule TTP_XOR_WriteProcessMemory_81ae {
  strings:
    $key_81ae = { d6 dc [2] e4 fe [2] e2 cb [2] cc cb [2] f3 d7 }

  condition:
    any of them
}