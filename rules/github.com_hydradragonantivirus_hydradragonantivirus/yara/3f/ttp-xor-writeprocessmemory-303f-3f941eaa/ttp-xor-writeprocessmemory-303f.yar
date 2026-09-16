rule TTP_XOR_WriteProcessMemory_303f {
  strings:
    $key_303f = { 67 4d [2] 55 6f [2] 53 5a [2] 7d 5a [2] 42 46 }

  condition:
    any of them
}