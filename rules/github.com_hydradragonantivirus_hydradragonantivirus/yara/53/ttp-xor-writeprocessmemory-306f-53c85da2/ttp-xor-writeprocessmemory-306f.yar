rule TTP_XOR_WriteProcessMemory_306f {
  strings:
    $key_306f = { 67 1d [2] 55 3f [2] 53 0a [2] 7d 0a [2] 42 16 }

  condition:
    any of them
}