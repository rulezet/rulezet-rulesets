rule TTP_XOR_WriteProcessMemory_251f {
  strings:
    $key_251f = { 72 6d [2] 40 4f [2] 46 7a [2] 68 7a [2] 57 66 }

  condition:
    any of them
}