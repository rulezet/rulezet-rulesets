rule TTP_XOR_WriteProcessMemory_161a {
  strings:
    $key_161a = { 41 68 [2] 73 4a [2] 75 7f [2] 5b 7f [2] 64 63 }

  condition:
    any of them
}