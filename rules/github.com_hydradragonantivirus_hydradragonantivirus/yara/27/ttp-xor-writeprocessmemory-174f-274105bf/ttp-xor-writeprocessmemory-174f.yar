rule TTP_XOR_WriteProcessMemory_174f {
  strings:
    $key_174f = { 40 3d [2] 72 1f [2] 74 2a [2] 5a 2a [2] 65 36 }

  condition:
    any of them
}