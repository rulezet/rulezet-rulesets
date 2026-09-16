rule TTP_XOR_WriteProcessMemory_ee8a {
  strings:
    $key_ee8a = { b9 f8 [2] 8b da [2] 8d ef [2] a3 ef [2] 9c f3 }

  condition:
    any of them
}