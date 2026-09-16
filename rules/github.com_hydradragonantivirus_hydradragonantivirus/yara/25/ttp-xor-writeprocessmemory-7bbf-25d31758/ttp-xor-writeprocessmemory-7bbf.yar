rule TTP_XOR_WriteProcessMemory_7bbf {
  strings:
    $key_7bbf = { 2c cd [2] 1e ef [2] 18 da [2] 36 da [2] 09 c6 }

  condition:
    any of them
}