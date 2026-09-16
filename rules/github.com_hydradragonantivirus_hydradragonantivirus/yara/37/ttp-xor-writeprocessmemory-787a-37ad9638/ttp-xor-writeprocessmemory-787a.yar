rule TTP_XOR_WriteProcessMemory_787a {
  strings:
    $key_787a = { 2f 08 [2] 1d 2a [2] 1b 1f [2] 35 1f [2] 0a 03 }

  condition:
    any of them
}