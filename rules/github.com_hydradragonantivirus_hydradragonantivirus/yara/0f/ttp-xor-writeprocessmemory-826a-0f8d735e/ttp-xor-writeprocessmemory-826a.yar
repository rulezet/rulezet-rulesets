rule TTP_XOR_WriteProcessMemory_826a {
  strings:
    $key_826a = { d5 18 [2] e7 3a [2] e1 0f [2] cf 0f [2] f0 13 }

  condition:
    any of them
}