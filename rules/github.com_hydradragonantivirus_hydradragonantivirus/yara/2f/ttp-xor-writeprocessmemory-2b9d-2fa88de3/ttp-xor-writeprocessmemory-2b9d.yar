rule TTP_XOR_WriteProcessMemory_2b9d {
  strings:
    $key_2b9d = { 7c ef [2] 4e cd [2] 48 f8 [2] 66 f8 [2] 59 e4 }

  condition:
    any of them
}