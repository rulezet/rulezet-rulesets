rule TTP_XOR_WriteProcessMemory_ce4f {
  strings:
    $key_ce4f = { 99 3d [2] ab 1f [2] ad 2a [2] 83 2a [2] bc 36 }

  condition:
    any of them
}