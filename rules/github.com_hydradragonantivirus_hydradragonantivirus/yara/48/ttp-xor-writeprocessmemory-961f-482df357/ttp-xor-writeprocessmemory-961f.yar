rule TTP_XOR_WriteProcessMemory_961f {
  strings:
    $key_961f = { c1 6d [2] f3 4f [2] f5 7a [2] db 7a [2] e4 66 }

  condition:
    any of them
}