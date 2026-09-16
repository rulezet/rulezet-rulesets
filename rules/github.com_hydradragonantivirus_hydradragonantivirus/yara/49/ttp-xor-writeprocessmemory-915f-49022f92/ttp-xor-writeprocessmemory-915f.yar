rule TTP_XOR_WriteProcessMemory_915f {
  strings:
    $key_915f = { c6 2d [2] f4 0f [2] f2 3a [2] dc 3a [2] e3 26 }

  condition:
    any of them
}