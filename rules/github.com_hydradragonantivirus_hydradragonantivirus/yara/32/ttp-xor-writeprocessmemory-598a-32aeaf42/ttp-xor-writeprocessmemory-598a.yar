rule TTP_XOR_WriteProcessMemory_598a {
  strings:
    $key_598a = { 0e f8 [2] 3c da [2] 3a ef [2] 14 ef [2] 2b f3 }

  condition:
    any of them
}