rule TTP_XOR_WriteProcessMemory_540a {
  strings:
    $key_540a = { 03 78 [2] 31 5a [2] 37 6f [2] 19 6f [2] 26 73 }

  condition:
    any of them
}