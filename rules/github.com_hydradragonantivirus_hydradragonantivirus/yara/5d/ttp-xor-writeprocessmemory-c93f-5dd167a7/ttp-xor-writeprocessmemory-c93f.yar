rule TTP_XOR_WriteProcessMemory_c93f {
  strings:
    $key_c93f = { 9e 4d [2] ac 6f [2] aa 5a [2] 84 5a [2] bb 46 }

  condition:
    any of them
}