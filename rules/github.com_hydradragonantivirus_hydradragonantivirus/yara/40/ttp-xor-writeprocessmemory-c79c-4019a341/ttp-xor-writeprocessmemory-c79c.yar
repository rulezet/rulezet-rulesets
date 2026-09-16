rule TTP_XOR_WriteProcessMemory_c79c {
  strings:
    $key_c79c = { 90 ee [2] a2 cc [2] a4 f9 [2] 8a f9 [2] b5 e5 }

  condition:
    any of them
}