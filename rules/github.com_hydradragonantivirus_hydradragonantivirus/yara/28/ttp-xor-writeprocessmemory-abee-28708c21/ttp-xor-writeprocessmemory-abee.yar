rule TTP_XOR_WriteProcessMemory_abee {
  strings:
    $key_abee = { fc 9c [2] ce be [2] c8 8b [2] e6 8b [2] d9 97 }

  condition:
    any of them
}