rule TTP_XOR_WriteProcessMemory_762f {
  strings:
    $key_762f = { 21 5d [2] 13 7f [2] 15 4a [2] 3b 4a [2] 04 56 }

  condition:
    any of them
}