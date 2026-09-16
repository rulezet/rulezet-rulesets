rule TTP_XOR_WriteProcessMemory_db80 {
  strings:
    $key_db80 = { 8c f2 [2] be d0 [2] b8 e5 [2] 96 e5 [2] a9 f9 }

  condition:
    any of them
}