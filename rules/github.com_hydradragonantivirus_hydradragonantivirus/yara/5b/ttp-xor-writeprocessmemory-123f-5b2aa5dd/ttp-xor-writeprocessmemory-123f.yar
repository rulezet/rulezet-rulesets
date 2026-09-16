rule TTP_XOR_WriteProcessMemory_123f {
  strings:
    $key_123f = { 45 4d [2] 77 6f [2] 71 5a [2] 5f 5a [2] 60 46 }

  condition:
    any of them
}