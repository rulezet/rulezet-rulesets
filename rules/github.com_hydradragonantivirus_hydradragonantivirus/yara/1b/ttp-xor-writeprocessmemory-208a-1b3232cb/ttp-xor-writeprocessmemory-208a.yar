rule TTP_XOR_WriteProcessMemory_208a {
  strings:
    $key_208a = { 77 f8 [2] 45 da [2] 43 ef [2] 6d ef [2] 52 f3 }

  condition:
    any of them
}