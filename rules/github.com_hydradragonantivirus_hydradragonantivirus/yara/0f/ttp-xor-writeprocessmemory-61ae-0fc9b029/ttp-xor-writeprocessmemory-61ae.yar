rule TTP_XOR_WriteProcessMemory_61ae {
  strings:
    $key_61ae = { 36 dc [2] 04 fe [2] 02 cb [2] 2c cb [2] 13 d7 }

  condition:
    any of them
}