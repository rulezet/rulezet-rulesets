rule TTP_XOR_WriteProcessMemory_eeca {
  strings:
    $key_eeca = { b9 b8 [2] 8b 9a [2] 8d af [2] a3 af [2] 9c b3 }

  condition:
    any of them
}