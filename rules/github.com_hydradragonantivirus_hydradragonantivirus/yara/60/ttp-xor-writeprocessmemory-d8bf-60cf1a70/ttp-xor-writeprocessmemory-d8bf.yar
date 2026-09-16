rule TTP_XOR_WriteProcessMemory_d8bf {
  strings:
    $key_d8bf = { 8f cd [2] bd ef [2] bb da [2] 95 da [2] aa c6 }

  condition:
    any of them
}