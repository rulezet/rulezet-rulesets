rule TTP_XOR_WriteProcessMemory_731a {
  strings:
    $key_731a = { 24 68 [2] 16 4a [2] 10 7f [2] 3e 7f [2] 01 63 }

  condition:
    any of them
}