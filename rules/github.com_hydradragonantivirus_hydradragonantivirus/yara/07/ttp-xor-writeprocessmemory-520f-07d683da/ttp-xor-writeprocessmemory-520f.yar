rule TTP_XOR_WriteProcessMemory_520f {
  strings:
    $key_520f = { 05 7d [2] 37 5f [2] 31 6a [2] 1f 6a [2] 20 76 }

  condition:
    any of them
}