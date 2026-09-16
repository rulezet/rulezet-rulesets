rule TTP_XOR_WriteProcessMemory_298a {
  strings:
    $key_298a = { 7e f8 [2] 4c da [2] 4a ef [2] 64 ef [2] 5b f3 }

  condition:
    any of them
}