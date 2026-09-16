rule TTP_XOR_WriteProcessMemory_91ea {
  strings:
    $key_91ea = { c6 98 [2] f4 ba [2] f2 8f [2] dc 8f [2] e3 93 }

  condition:
    any of them
}