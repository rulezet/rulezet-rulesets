rule TTP_XOR_WriteProcessMemory_103a {
  strings:
    $key_103a = { 47 48 [2] 75 6a [2] 73 5f [2] 5d 5f [2] 62 43 }

  condition:
    any of them
}