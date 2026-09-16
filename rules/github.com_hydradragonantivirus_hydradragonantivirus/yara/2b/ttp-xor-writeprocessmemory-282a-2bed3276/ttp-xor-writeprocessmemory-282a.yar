rule TTP_XOR_WriteProcessMemory_282a {
  strings:
    $key_282a = { 7f 58 [2] 4d 7a [2] 4b 4f [2] 65 4f [2] 5a 53 }

  condition:
    any of them
}