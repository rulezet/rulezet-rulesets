rule TTP_XOR_WriteProcessMemory_db8a {
  strings:
    $key_db8a = { 8c f8 [2] be da [2] b8 ef [2] 96 ef [2] a9 f3 }

  condition:
    any of them
}