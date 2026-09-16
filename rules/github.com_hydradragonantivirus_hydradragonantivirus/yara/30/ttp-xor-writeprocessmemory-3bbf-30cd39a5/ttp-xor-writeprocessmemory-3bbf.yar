rule TTP_XOR_WriteProcessMemory_3bbf {
  strings:
    $key_3bbf = { 6c cd [2] 5e ef [2] 58 da [2] 76 da [2] 49 c6 }

  condition:
    any of them
}