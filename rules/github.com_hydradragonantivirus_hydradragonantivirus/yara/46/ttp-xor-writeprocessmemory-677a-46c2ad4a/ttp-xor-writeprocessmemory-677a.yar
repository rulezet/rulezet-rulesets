rule TTP_XOR_WriteProcessMemory_677a {
  strings:
    $key_677a = { 30 08 [2] 02 2a [2] 04 1f [2] 2a 1f [2] 15 03 }

  condition:
    any of them
}