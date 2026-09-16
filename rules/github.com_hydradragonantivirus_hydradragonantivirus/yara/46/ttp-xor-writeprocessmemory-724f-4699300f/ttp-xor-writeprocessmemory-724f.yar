rule TTP_XOR_WriteProcessMemory_724f {
  strings:
    $key_724f = { 25 3d [2] 17 1f [2] 11 2a [2] 3f 2a [2] 00 36 }

  condition:
    any of them
}