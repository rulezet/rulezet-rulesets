rule TTP_XOR_WriteProcessMemory_c90d {
  strings:
    $key_c90d = { 9e 7f [2] ac 5d [2] aa 68 [2] 84 68 [2] bb 74 }

  condition:
    any of them
}