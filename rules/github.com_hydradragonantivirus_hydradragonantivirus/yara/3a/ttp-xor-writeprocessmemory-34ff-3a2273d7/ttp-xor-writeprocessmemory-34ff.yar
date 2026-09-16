rule TTP_XOR_WriteProcessMemory_34ff {
  strings:
    $key_34ff = { 63 8d [2] 51 af [2] 57 9a [2] 79 9a [2] 46 86 }

  condition:
    any of them
}