rule TTP_XOR_WriteProcessMemory_657a {
  strings:
    $key_657a = { 32 08 [2] 00 2a [2] 06 1f [2] 28 1f [2] 17 03 }

  condition:
    any of them
}