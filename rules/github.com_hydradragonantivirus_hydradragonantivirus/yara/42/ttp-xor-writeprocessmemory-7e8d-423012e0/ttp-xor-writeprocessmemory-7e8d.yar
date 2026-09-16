rule TTP_XOR_WriteProcessMemory_7e8d {
  strings:
    $key_7e8d = { 29 ff [2] 1b dd [2] 1d e8 [2] 33 e8 [2] 0c f4 }

  condition:
    any of them
}