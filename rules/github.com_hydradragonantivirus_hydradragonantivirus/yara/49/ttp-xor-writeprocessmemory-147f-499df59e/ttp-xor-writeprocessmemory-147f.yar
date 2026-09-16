rule TTP_XOR_WriteProcessMemory_147f {
  strings:
    $key_147f = { 43 0d [2] 71 2f [2] 77 1a [2] 59 1a [2] 66 06 }

  condition:
    any of them
}