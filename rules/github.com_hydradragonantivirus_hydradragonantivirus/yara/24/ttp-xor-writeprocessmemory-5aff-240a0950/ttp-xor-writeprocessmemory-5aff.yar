rule TTP_XOR_WriteProcessMemory_5aff {
  strings:
    $key_5aff = { 0d 8d [2] 3f af [2] 39 9a [2] 17 9a [2] 28 86 }

  condition:
    any of them
}