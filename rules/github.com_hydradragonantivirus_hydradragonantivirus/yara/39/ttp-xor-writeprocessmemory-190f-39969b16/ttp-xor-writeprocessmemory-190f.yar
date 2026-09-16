rule TTP_XOR_WriteProcessMemory_190f {
  strings:
    $key_190f = { 4e 7d [2] 7c 5f [2] 7a 6a [2] 54 6a [2] 6b 76 }

  condition:
    any of them
}