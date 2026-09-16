rule TTP_XOR_WriteProcessMemory_517a {
  strings:
    $key_517a = { 06 08 [2] 34 2a [2] 32 1f [2] 1c 1f [2] 23 03 }

  condition:
    any of them
}