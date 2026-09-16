rule TTP_XOR_WriteProcessMemory_438a {
  strings:
    $key_438a = { 14 f8 [2] 26 da [2] 20 ef [2] 0e ef [2] 31 f3 }

  condition:
    any of them
}