rule TTP_XOR_WriteProcessMemory_117a {
  strings:
    $key_117a = { 46 08 [2] 74 2a [2] 72 1f [2] 5c 1f [2] 63 03 }

  condition:
    any of them
}