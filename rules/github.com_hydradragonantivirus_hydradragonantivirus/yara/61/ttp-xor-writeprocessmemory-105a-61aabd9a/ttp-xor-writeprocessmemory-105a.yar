rule TTP_XOR_WriteProcessMemory_105a {
  strings:
    $key_105a = { 47 28 [2] 75 0a [2] 73 3f [2] 5d 3f [2] 62 23 }

  condition:
    any of them
}