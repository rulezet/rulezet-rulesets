rule TTP_XOR_WriteProcessMemory_960a {
  strings:
    $key_960a = { c1 78 [2] f3 5a [2] f5 6f [2] db 6f [2] e4 73 }

  condition:
    any of them
}