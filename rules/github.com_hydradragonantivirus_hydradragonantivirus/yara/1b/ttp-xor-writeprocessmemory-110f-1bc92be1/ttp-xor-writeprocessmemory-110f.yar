rule TTP_XOR_WriteProcessMemory_110f {
  strings:
    $key_110f = { 46 7d [2] 74 5f [2] 72 6a [2] 5c 6a [2] 63 76 }

  condition:
    any of them
}