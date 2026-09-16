rule TTP_XOR_WriteProcessMemory_ef8a {
  strings:
    $key_ef8a = { b8 f8 [2] 8a da [2] 8c ef [2] a2 ef [2] 9d f3 }

  condition:
    any of them
}