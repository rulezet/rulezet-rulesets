rule TTP_XOR_WriteProcessMemory_c94a {
  strings:
    $key_c94a = { 9e 38 [2] ac 1a [2] aa 2f [2] 84 2f [2] bb 33 }

  condition:
    any of them
}