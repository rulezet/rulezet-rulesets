rule TTP_XOR_WriteProcessMemory_412a {
  strings:
    $key_412a = { 16 58 [2] 24 7a [2] 22 4f [2] 0c 4f [2] 33 53 }

  condition:
    any of them
}