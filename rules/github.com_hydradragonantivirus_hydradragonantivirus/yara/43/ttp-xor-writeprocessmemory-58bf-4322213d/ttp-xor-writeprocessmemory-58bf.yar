rule TTP_XOR_WriteProcessMemory_58bf {
  strings:
    $key_58bf = { 0f cd [2] 3d ef [2] 3b da [2] 15 da [2] 2a c6 }

  condition:
    any of them
}