rule TTP_XOR_WriteProcessMemory_c90f {
  strings:
    $key_c90f = { 9e 7d [2] ac 5f [2] aa 6a [2] 84 6a [2] bb 76 }

  condition:
    any of them
}