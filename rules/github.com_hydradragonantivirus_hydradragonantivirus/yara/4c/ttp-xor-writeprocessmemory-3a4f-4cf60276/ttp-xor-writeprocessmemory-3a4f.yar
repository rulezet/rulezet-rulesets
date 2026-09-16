rule TTP_XOR_WriteProcessMemory_3a4f {
  strings:
    $key_3a4f = { 6d 3d [2] 5f 1f [2] 59 2a [2] 77 2a [2] 48 36 }

  condition:
    any of them
}