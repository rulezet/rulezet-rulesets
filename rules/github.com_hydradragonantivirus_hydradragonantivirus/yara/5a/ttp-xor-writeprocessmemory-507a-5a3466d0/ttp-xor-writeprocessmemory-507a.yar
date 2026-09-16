rule TTP_XOR_WriteProcessMemory_507a {
  strings:
    $key_507a = { 07 08 [2] 35 2a [2] 33 1f [2] 1d 1f [2] 22 03 }

  condition:
    any of them
}