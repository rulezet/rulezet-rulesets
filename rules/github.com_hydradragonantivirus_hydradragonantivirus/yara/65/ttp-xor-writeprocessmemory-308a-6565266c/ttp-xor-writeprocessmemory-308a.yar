rule TTP_XOR_WriteProcessMemory_308a {
  strings:
    $key_308a = { 67 f8 [2] 55 da [2] 53 ef [2] 7d ef [2] 42 f3 }

  condition:
    any of them
}