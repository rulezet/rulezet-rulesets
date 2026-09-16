rule TTP_XOR_WriteProcessMemory_f8bf {
  strings:
    $key_f8bf = { af cd [2] 9d ef [2] 9b da [2] b5 da [2] 8a c6 }

  condition:
    any of them
}