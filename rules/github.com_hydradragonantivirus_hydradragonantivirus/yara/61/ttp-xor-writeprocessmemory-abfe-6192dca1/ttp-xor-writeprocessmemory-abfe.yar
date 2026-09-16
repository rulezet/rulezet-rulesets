rule TTP_XOR_WriteProcessMemory_abfe {
  strings:
    $key_abfe = { fc 8c [2] ce ae [2] c8 9b [2] e6 9b [2] d9 87 }

  condition:
    any of them
}