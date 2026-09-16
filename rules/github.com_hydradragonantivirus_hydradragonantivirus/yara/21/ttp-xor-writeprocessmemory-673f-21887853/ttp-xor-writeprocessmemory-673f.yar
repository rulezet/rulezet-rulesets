rule TTP_XOR_WriteProcessMemory_673f {
  strings:
    $key_673f = { 30 4d [2] 02 6f [2] 04 5a [2] 2a 5a [2] 15 46 }

  condition:
    any of them
}