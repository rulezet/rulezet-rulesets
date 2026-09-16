rule TTP_XOR_WriteProcessMemory_127f {
  strings:
    $key_127f = { 45 0d [2] 77 2f [2] 71 1a [2] 5f 1a [2] 60 06 }

  condition:
    any of them
}