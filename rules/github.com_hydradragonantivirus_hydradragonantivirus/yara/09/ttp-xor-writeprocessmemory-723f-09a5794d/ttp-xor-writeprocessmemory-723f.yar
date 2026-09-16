rule TTP_XOR_WriteProcessMemory_723f {
  strings:
    $key_723f = { 25 4d [2] 17 6f [2] 11 5a [2] 3f 5a [2] 00 46 }

  condition:
    any of them
}