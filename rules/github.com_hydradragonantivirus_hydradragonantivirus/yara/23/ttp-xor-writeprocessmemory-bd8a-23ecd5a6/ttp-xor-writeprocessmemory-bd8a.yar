rule TTP_XOR_WriteProcessMemory_bd8a {
  strings:
    $key_bd8a = { ea f8 [2] d8 da [2] de ef [2] f0 ef [2] cf f3 }

  condition:
    any of them
}