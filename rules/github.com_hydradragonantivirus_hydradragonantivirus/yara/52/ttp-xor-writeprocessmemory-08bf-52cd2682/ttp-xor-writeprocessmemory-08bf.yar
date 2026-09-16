rule TTP_XOR_WriteProcessMemory_08bf {
  strings:
    $key_08bf = { 5f cd [2] 6d ef [2] 6b da [2] 45 da [2] 7a c6 }

  condition:
    any of them
}