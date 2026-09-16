rule TTP_XOR_WriteProcessMemory_760a {
  strings:
    $key_760a = { 21 78 [2] 13 5a [2] 15 6f [2] 3b 6f [2] 04 73 }

  condition:
    any of them
}