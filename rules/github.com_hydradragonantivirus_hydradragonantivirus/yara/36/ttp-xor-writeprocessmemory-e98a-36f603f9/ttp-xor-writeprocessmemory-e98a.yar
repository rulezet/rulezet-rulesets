rule TTP_XOR_WriteProcessMemory_e98a {
  strings:
    $key_e98a = { be f8 [2] 8c da [2] 8a ef [2] a4 ef [2] 9b f3 }

  condition:
    any of them
}