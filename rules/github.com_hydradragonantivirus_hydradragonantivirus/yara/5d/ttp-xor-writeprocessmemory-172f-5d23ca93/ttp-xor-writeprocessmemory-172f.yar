rule TTP_XOR_WriteProcessMemory_172f {
  strings:
    $key_172f = { 40 5d [2] 72 7f [2] 74 4a [2] 5a 4a [2] 65 56 }

  condition:
    any of them
}