rule TTP_XOR_WriteProcessMemory_063f {
  strings:
    $key_063f = { 51 4d [2] 63 6f [2] 65 5a [2] 4b 5a [2] 74 46 }

  condition:
    any of them
}