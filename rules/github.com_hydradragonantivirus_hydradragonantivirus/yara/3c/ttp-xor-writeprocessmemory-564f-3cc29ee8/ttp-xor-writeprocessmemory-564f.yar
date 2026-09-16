rule TTP_XOR_WriteProcessMemory_564f {
  strings:
    $key_564f = { 01 3d [2] 33 1f [2] 35 2a [2] 1b 2a [2] 24 36 }

  condition:
    any of them
}