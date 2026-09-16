rule TTP_XOR_WriteProcessMemory_702a {
  strings:
    $key_702a = { 27 58 [2] 15 7a [2] 13 4f [2] 3d 4f [2] 02 53 }

  condition:
    any of them
}