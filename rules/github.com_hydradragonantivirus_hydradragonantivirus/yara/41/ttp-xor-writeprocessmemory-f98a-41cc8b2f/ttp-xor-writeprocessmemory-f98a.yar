rule TTP_XOR_WriteProcessMemory_f98a {
  strings:
    $key_f98a = { ae f8 [2] 9c da [2] 9a ef [2] b4 ef [2] 8b f3 }

  condition:
    any of them
}