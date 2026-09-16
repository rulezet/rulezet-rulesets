rule TTP_XOR_WriteProcessMemory_285a {
  strings:
    $key_285a = { 7f 28 [2] 4d 0a [2] 4b 3f [2] 65 3f [2] 5a 23 }

  condition:
    any of them
}