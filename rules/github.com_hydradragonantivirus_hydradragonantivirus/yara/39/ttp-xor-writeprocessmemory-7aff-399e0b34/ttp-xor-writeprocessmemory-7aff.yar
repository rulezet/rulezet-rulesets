rule TTP_XOR_WriteProcessMemory_7aff {
  strings:
    $key_7aff = { 2d 8d [2] 1f af [2] 19 9a [2] 37 9a [2] 08 86 }

  condition:
    any of them
}