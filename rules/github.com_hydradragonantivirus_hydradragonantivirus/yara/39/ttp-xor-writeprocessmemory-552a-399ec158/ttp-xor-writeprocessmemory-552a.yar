rule TTP_XOR_WriteProcessMemory_552a {
  strings:
    $key_552a = { 02 58 [2] 30 7a [2] 36 4f [2] 18 4f [2] 27 53 }

  condition:
    any of them
}