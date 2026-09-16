rule TTP_XOR_WriteProcessMemory_761a {
  strings:
    $key_761a = { 21 68 [2] 13 4a [2] 15 7f [2] 3b 7f [2] 04 63 }

  condition:
    any of them
}