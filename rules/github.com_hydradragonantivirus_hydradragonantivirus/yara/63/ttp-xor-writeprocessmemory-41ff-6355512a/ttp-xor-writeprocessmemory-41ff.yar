rule TTP_XOR_WriteProcessMemory_41ff {
  strings:
    $key_41ff = { 16 8d [2] 24 af [2] 22 9a [2] 0c 9a [2] 33 86 }

  condition:
    any of them
}