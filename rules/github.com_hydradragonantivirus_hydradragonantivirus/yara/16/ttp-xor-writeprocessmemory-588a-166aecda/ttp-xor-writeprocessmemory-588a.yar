rule TTP_XOR_WriteProcessMemory_588a {
  strings:
    $key_588a = { 0f f8 [2] 3d da [2] 3b ef [2] 15 ef [2] 2a f3 }

  condition:
    any of them
}