rule TTP_XOR_WriteProcessMemory_220a {
  strings:
    $key_220a = { 75 78 [2] 47 5a [2] 41 6f [2] 6f 6f [2] 50 73 }

  condition:
    any of them
}