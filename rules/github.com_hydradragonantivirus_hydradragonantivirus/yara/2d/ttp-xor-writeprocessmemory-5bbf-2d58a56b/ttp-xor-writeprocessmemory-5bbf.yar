rule TTP_XOR_WriteProcessMemory_5bbf {
  strings:
    $key_5bbf = { 0c cd [2] 3e ef [2] 38 da [2] 16 da [2] 29 c6 }

  condition:
    any of them
}