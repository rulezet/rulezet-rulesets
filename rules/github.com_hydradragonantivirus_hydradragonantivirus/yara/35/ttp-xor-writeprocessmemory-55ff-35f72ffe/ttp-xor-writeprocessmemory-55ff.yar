rule TTP_XOR_WriteProcessMemory_55ff {
  strings:
    $key_55ff = { 02 8d [2] 30 af [2] 36 9a [2] 18 9a [2] 27 86 }

  condition:
    any of them
}