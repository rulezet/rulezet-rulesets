rule TTP_XOR_WriteProcessMemory_a3ae {
  strings:
    $key_a3ae = { f4 dc [2] c6 fe [2] c0 cb [2] ee cb [2] d1 d7 }

  condition:
    any of them
}