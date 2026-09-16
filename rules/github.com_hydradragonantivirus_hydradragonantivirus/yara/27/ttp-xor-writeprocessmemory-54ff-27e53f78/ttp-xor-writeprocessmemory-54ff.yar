rule TTP_XOR_WriteProcessMemory_54ff {
  strings:
    $key_54ff = { 03 8d [2] 31 af [2] 37 9a [2] 19 9a [2] 26 86 }

  condition:
    any of them
}