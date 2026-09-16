rule TTP_XOR_WriteProcessMemory_c91f {
  strings:
    $key_c91f = { 9e 6d [2] ac 4f [2] aa 7a [2] 84 7a [2] bb 66 }

  condition:
    any of them
}