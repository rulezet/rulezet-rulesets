rule TTP_XOR_WriteProcessMemory_f06d {
  strings:
    $key_f06d = { a7 1f [2] 95 3d [2] 93 08 [2] bd 08 [2] 82 14 }

  condition:
    any of them
}