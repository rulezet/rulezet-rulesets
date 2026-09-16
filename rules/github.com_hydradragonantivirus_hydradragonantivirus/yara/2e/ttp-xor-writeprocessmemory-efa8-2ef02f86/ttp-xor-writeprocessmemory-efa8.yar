rule TTP_XOR_WriteProcessMemory_efa8 {
  strings:
    $key_efa8 = { b8 da [2] 8a f8 [2] 8c cd [2] a2 cd [2] 9d d1 }

  condition:
    any of them
}