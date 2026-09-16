rule TTP_XOR_WriteProcessMemory_003f {
  strings:
    $key_003f = { 57 4d [2] 65 6f [2] 63 5a [2] 4d 5a [2] 72 46 }

  condition:
    any of them
}