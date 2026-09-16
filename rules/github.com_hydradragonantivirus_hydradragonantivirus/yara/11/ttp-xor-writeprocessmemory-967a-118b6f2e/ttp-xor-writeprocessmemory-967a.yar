rule TTP_XOR_WriteProcessMemory_967a {
  strings:
    $key_967a = { c1 08 [2] f3 2a [2] f5 1f [2] db 1f [2] e4 03 }

  condition:
    any of them
}