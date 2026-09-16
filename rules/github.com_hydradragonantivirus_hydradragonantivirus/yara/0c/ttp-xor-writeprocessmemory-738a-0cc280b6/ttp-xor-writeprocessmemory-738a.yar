rule TTP_XOR_WriteProcessMemory_738a {
  strings:
    $key_738a = { 24 f8 [2] 16 da [2] 10 ef [2] 3e ef [2] 01 f3 }

  condition:
    any of them
}