rule TTP_XOR_WriteProcessMemory_e3ae {
  strings:
    $key_e3ae = { b4 dc [2] 86 fe [2] 80 cb [2] ae cb [2] 91 d7 }

  condition:
    any of them
}