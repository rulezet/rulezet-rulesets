rule TTP_XOR_WriteProcessMemory_ab9b {
  strings:
    $key_ab9b = { fc e9 [2] ce cb [2] c8 fe [2] e6 fe [2] d9 e2 }

  condition:
    any of them
}