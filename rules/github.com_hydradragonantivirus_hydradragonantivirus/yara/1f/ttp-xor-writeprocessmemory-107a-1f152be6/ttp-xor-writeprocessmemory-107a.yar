rule TTP_XOR_WriteProcessMemory_107a {
  strings:
    $key_107a = { 47 08 [2] 75 2a [2] 73 1f [2] 5d 1f [2] 62 03 }

  condition:
    any of them
}