rule TTP_XOR_WriteProcessMemory_788a {
  strings:
    $key_788a = { 2f f8 [2] 1d da [2] 1b ef [2] 35 ef [2] 0a f3 }

  condition:
    any of them
}