rule TTP_XOR_WriteProcessMemory_99cc {
  strings:
    $key_99cc = { ce be [2] fc 9c [2] fa a9 [2] d4 a9 [2] eb b5 }

  condition:
    any of them
}