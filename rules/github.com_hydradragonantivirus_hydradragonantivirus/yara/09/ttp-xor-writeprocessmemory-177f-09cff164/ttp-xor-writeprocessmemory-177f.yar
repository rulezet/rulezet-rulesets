rule TTP_XOR_WriteProcessMemory_177f {
  strings:
    $key_177f = { 40 0d [2] 72 2f [2] 74 1a [2] 5a 1a [2] 65 06 }

  condition:
    any of them
}