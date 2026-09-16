rule TTP_XOR_WriteProcessMemory_ad9b {
  strings:
    $key_ad9b = { fa e9 [2] c8 cb [2] ce fe [2] e0 fe [2] df e2 }

  condition:
    any of them
}