rule TTP_XOR_WriteProcessMemory_e38a {
  strings:
    $key_e38a = { b4 f8 [2] 86 da [2] 80 ef [2] ae ef [2] 91 f3 }

  condition:
    any of them
}