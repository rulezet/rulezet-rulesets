rule TTP_XOR_WriteProcessMemory_948a {
  strings:
    $key_948a = { c3 f8 [2] f1 da [2] f7 ef [2] d9 ef [2] e6 f3 }

  condition:
    any of them
}