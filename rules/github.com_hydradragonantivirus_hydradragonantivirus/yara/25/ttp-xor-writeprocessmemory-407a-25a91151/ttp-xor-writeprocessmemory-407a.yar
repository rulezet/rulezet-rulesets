rule TTP_XOR_WriteProcessMemory_407a {
  strings:
    $key_407a = { 17 08 [2] 25 2a [2] 23 1f [2] 0d 1f [2] 32 03 }

  condition:
    any of them
}