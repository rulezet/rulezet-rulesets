rule TTP_XOR_WriteProcessMemory_798a {
  strings:
    $key_798a = { 2e f8 [2] 1c da [2] 1a ef [2] 34 ef [2] 0b f3 }

  condition:
    any of them
}