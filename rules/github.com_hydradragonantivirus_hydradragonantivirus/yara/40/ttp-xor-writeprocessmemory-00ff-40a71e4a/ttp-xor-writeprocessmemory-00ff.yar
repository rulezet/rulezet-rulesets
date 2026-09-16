rule TTP_XOR_WriteProcessMemory_00ff {
  strings:
    $key_00ff = { 57 8d [2] 65 af [2] 63 9a [2] 4d 9a [2] 72 86 }

  condition:
    any of them
}