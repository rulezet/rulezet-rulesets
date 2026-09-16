rule TTP_XOR_WriteProcessMemory_68bf {
  strings:
    $key_68bf = { 3f cd [2] 0d ef [2] 0b da [2] 25 da [2] 1a c6 }

  condition:
    any of them
}