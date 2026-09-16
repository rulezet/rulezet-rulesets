rule TTP_XOR_WriteProcessMemory_fcae {
  strings:
    $key_fcae = { ab dc [2] 99 fe [2] 9f cb [2] b1 cb [2] 8e d7 }

  condition:
    any of them
}