rule TTP_XOR_WriteProcessMemory_288d {
  strings:
    $key_288d = { 7f ff [2] 4d dd [2] 4b e8 [2] 65 e8 [2] 5a f4 }

  condition:
    any of them
}