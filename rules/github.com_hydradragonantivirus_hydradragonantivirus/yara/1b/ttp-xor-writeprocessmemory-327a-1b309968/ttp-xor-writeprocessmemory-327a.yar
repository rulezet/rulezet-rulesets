rule TTP_XOR_WriteProcessMemory_327a {
  strings:
    $key_327a = { 65 08 [2] 57 2a [2] 51 1f [2] 7f 1f [2] 40 03 }

  condition:
    any of them
}