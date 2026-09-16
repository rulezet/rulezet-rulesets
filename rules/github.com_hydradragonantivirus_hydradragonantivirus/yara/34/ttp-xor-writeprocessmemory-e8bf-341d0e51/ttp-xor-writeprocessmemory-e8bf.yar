rule TTP_XOR_WriteProcessMemory_e8bf {
  strings:
    $key_e8bf = { bf cd [2] 8d ef [2] 8b da [2] a5 da [2] 9a c6 }

  condition:
    any of them
}