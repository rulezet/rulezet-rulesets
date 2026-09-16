rule TTP_XOR_WriteProcessMemory_488d {
  strings:
    $key_488d = { 1f ff [2] 2d dd [2] 2b e8 [2] 05 e8 [2] 3a f4 }

  condition:
    any of them
}