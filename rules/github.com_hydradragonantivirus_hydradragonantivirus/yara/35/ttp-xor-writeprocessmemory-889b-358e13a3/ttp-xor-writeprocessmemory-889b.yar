rule TTP_XOR_WriteProcessMemory_889b {
  strings:
    $key_889b = { df e9 [2] ed cb [2] eb fe [2] c5 fe [2] fa e2 }

  condition:
    any of them
}