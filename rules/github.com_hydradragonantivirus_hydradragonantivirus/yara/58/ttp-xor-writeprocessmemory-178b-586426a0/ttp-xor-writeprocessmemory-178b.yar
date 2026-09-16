rule TTP_XOR_WriteProcessMemory_178b {
  strings:
    $key_178b = { 40 f9 [2] 72 db [2] 74 ee [2] 5a ee [2] 65 f2 }

  condition:
    any of them
}