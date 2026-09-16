rule TTP_XOR_WriteProcessMemory_514a {
  strings:
    $key_514a = { 06 38 [2] 34 1a [2] 32 2f [2] 1c 2f [2] 23 33 }

  condition:
    any of them
}