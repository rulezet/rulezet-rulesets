rule TTP_XOR_WriteProcessMemory_f97f {
  strings:
    $key_f97f = { ae 0d [2] 9c 2f [2] 9a 1a [2] b4 1a [2] 8b 06 }

  condition:
    any of them
}