rule TTP_XOR_WriteProcessMemory_320a {
  strings:
    $key_320a = { 65 78 [2] 57 5a [2] 51 6f [2] 7f 6f [2] 40 73 }

  condition:
    any of them
}