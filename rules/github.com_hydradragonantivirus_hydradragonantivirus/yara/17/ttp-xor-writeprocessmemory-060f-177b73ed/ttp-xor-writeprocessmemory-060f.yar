rule TTP_XOR_WriteProcessMemory_060f {
  strings:
    $key_060f = { 51 7d [2] 63 5f [2] 65 6a [2] 4b 6a [2] 74 76 }

  condition:
    any of them
}