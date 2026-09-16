rule TTP_XOR_WriteProcessMemory_e89d {
  strings:
    $key_e89d = { bf ef [2] 8d cd [2] 8b f8 [2] a5 f8 [2] 9a e4 }

  condition:
    any of them
}