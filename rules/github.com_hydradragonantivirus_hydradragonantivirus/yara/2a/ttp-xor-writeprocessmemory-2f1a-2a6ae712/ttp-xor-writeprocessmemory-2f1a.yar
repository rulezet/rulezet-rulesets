rule TTP_XOR_WriteProcessMemory_2f1a {
  strings:
    $key_2f1a = { 78 68 [2] 4a 4a [2] 4c 7f [2] 62 7f [2] 5d 63 }

  condition:
    any of them
}