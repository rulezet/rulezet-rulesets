rule TTP_XOR_WriteProcessMemory_979b {
  strings:
    $key_979b = { c0 e9 [2] f2 cb [2] f4 fe [2] da fe [2] e5 e2 }

  condition:
    any of them
}