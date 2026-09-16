rule TTP_XOR_WriteProcessMemory_69ff {
  strings:
    $key_69ff = { 3e 8d [2] 0c af [2] 0a 9a [2] 24 9a [2] 1b 86 }

  condition:
    any of them
}