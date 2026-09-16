rule TTP_XOR_WriteProcessMemory_f14f {
  strings:
    $key_f14f = { a6 3d [2] 94 1f [2] 92 2a [2] bc 2a [2] 83 36 }

  condition:
    any of them
}