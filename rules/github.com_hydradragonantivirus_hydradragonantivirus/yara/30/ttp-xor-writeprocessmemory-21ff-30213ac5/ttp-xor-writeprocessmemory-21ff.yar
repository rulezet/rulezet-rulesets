rule TTP_XOR_WriteProcessMemory_21ff {
  strings:
    $key_21ff = { 76 8d [2] 44 af [2] 42 9a [2] 6c 9a [2] 53 86 }

  condition:
    any of them
}