rule TTP_XOR_WriteProcessMemory_698a {
  strings:
    $key_698a = { 3e f8 [2] 0c da [2] 0a ef [2] 24 ef [2] 1b f3 }

  condition:
    any of them
}