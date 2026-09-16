rule TTP_XOR_WriteProcessMemory_52ff {
  strings:
    $key_52ff = { 05 8d [2] 37 af [2] 31 9a [2] 1f 9a [2] 20 86 }

  condition:
    any of them
}