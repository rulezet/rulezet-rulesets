rule TTP_XOR_WriteProcessMemory_034a {
  strings:
    $key_034a = { 54 38 [2] 66 1a [2] 60 2f [2] 4e 2f [2] 71 33 }

  condition:
    any of them
}