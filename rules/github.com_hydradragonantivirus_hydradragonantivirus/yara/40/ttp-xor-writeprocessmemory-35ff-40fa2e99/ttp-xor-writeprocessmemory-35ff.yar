rule TTP_XOR_WriteProcessMemory_35ff {
  strings:
    $key_35ff = { 62 8d [2] 50 af [2] 56 9a [2] 78 9a [2] 47 86 }

  condition:
    any of them
}