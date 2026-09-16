rule TTP_XOR_WriteProcessMemory_365d {
  strings:
    $key_365d = { 61 2f [2] 53 0d [2] 55 38 [2] 7b 38 [2] 44 24 }

  condition:
    any of them
}