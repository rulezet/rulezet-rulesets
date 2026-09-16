rule TTP_XOR_WriteProcessMemory_1e3f {
  strings:
    $key_1e3f = { 49 4d [2] 7b 6f [2] 7d 5a [2] 53 5a [2] 6c 46 }

  condition:
    any of them
}