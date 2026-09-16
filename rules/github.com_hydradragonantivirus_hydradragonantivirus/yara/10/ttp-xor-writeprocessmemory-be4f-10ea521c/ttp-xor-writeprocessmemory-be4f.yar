rule TTP_XOR_WriteProcessMemory_be4f {
  strings:
    $key_be4f = { e9 3d [2] db 1f [2] dd 2a [2] f3 2a [2] cc 36 }

  condition:
    any of them
}