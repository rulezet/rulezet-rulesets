rule TTP_XOR_WriteProcessMemory_4bbf {
  strings:
    $key_4bbf = { 1c cd [2] 2e ef [2] 28 da [2] 06 da [2] 39 c6 }

  condition:
    any of them
}