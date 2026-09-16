rule TTP_XOR_WriteProcessMemory_223f {
  strings:
    $key_223f = { 75 4d [2] 47 6f [2] 41 5a [2] 6f 5a [2] 50 46 }

  condition:
    any of them
}