rule TTP_XOR_WriteProcessMemory_8b8a {
  strings:
    $key_8b8a = { dc f8 [2] ee da [2] e8 ef [2] c6 ef [2] f9 f3 }

  condition:
    any of them
}