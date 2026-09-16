rule TTP_XOR_WriteProcessMemory_688a {
  strings:
    $key_688a = { 3f f8 [2] 0d da [2] 0b ef [2] 25 ef [2] 1a f3 }

  condition:
    any of them
}