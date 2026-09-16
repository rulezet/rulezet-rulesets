rule TTP_XOR_WriteProcessMemory_839b {
  strings:
    $key_839b = { d4 e9 [2] e6 cb [2] e0 fe [2] ce fe [2] f1 e2 }

  condition:
    any of them
}