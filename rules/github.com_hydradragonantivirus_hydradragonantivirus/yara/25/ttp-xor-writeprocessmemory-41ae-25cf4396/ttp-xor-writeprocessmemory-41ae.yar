rule TTP_XOR_WriteProcessMemory_41ae {
  strings:
    $key_41ae = { 16 dc [2] 24 fe [2] 22 cb [2] 0c cb [2] 33 d7 }

  condition:
    any of them
}