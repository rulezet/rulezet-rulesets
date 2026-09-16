rule TTP_XOR_WriteProcessMemory_18bf {
  strings:
    $key_18bf = { 4f cd [2] 7d ef [2] 7b da [2] 55 da [2] 6a c6 }

  condition:
    any of them
}