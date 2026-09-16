rule TTP_XOR_WriteProcessMemory_d9b6 {
  strings:
    $key_d9b6 = { 8e c4 [2] bc e6 [2] ba d3 [2] 94 d3 [2] ab cf }

  condition:
    any of them
}