rule TTP_XOR_WriteProcessMemory_243a {
  strings:
    $key_243a = { 73 48 [2] 41 6a [2] 47 5f [2] 69 5f [2] 56 43 }

  condition:
    any of them
}