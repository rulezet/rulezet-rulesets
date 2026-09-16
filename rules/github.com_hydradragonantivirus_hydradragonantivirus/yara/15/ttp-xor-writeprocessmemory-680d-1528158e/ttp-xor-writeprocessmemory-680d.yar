rule TTP_XOR_WriteProcessMemory_680d {
  strings:
    $key_680d = { 3f 7f [2] 0d 5d [2] 0b 68 [2] 25 68 [2] 1a 74 }

  condition:
    any of them
}