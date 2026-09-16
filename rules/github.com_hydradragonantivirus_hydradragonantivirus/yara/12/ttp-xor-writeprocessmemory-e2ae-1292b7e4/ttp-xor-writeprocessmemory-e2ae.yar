rule TTP_XOR_WriteProcessMemory_e2ae {
  strings:
    $key_e2ae = { b5 dc [2] 87 fe [2] 81 cb [2] af cb [2] 90 d7 }

  condition:
    any of them
}