rule TTP_XOR_WriteProcessMemory_fece {
  strings:
    $key_fece = { a9 bc [2] 9b 9e [2] 9d ab [2] b3 ab [2] 8c b7 }

  condition:
    any of them
}