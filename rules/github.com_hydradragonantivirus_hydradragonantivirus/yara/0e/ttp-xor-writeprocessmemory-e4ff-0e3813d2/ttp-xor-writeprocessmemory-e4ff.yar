rule TTP_XOR_WriteProcessMemory_e4ff {
  strings:
    $key_e4ff = { b3 8d [2] 81 af [2] 87 9a [2] a9 9a [2] 96 86 }

  condition:
    any of them
}