rule TTP_XOR_WriteProcessMemory_c08b {
  strings:
    $key_c08b = { 97 f9 [2] a5 db [2] a3 ee [2] 8d ee [2] b2 f2 }

  condition:
    any of them
}