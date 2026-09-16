rule TTP_XOR_WriteProcessMemory_652a {
  strings:
    $key_652a = { 32 58 [2] 00 7a [2] 06 4f [2] 28 4f [2] 17 53 }

  condition:
    any of them
}