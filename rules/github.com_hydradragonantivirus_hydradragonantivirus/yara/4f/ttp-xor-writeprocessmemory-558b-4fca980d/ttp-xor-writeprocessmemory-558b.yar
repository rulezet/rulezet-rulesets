rule TTP_XOR_WriteProcessMemory_558b {
  strings:
    $key_558b = { 02 f9 [2] 30 db [2] 36 ee [2] 18 ee [2] 27 f2 }

  condition:
    any of them
}