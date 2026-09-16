rule TTP_XOR_WriteProcessMemory_42ff {
  strings:
    $key_42ff = { 15 8d [2] 27 af [2] 21 9a [2] 0f 9a [2] 30 86 }

  condition:
    any of them
}