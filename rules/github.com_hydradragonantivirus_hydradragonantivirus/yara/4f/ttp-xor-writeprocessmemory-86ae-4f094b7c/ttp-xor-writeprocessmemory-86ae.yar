rule TTP_XOR_WriteProcessMemory_86ae {
  strings:
    $key_86ae = { d1 dc [2] e3 fe [2] e5 cb [2] cb cb [2] f4 d7 }

  condition:
    any of them
}