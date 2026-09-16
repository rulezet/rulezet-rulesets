rule TTP_XOR_WriteProcessMemory_f08a {
  strings:
    $key_f08a = { a7 f8 [2] 95 da [2] 93 ef [2] bd ef [2] 82 f3 }

  condition:
    any of them
}