rule TTP_XOR_WriteProcessMemory_4aff {
  strings:
    $key_4aff = { 1d 8d [2] 2f af [2] 29 9a [2] 07 9a [2] 38 86 }

  condition:
    any of them
}