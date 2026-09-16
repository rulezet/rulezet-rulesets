rule TTP_XOR_WriteProcessMemory_370f {
  strings:
    $key_370f = { 60 7d [2] 52 5f [2] 54 6a [2] 7a 6a [2] 45 76 }

  condition:
    any of them
}