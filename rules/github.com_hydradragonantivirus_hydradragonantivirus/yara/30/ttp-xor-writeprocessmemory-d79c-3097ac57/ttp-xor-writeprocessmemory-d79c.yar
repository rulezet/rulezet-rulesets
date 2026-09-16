rule TTP_XOR_WriteProcessMemory_d79c {
  strings:
    $key_d79c = { 80 ee [2] b2 cc [2] b4 f9 [2] 9a f9 [2] a5 e5 }

  condition:
    any of them
}