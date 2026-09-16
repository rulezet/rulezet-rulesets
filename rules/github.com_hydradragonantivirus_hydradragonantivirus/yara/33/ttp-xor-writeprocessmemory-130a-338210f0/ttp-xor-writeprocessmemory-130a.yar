rule TTP_XOR_WriteProcessMemory_130a {
  strings:
    $key_130a = { 44 78 [2] 76 5a [2] 70 6f [2] 5e 6f [2] 61 73 }

  condition:
    any of them
}