rule TTP_XOR_WriteProcessMemory_6bbf {
  strings:
    $key_6bbf = { 3c cd [2] 0e ef [2] 08 da [2] 26 da [2] 19 c6 }

  condition:
    any of them
}