rule TTP_XOR_WriteProcessMemory_cc8a {
  strings:
    $key_cc8a = { 9b f8 [2] a9 da [2] af ef [2] 81 ef [2] be f3 }

  condition:
    any of them
}