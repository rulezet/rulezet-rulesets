rule TTP_XOR_WriteProcessMemory_dc8a {
  strings:
    $key_dc8a = { 8b f8 [2] b9 da [2] bf ef [2] 91 ef [2] ae f3 }

  condition:
    any of them
}