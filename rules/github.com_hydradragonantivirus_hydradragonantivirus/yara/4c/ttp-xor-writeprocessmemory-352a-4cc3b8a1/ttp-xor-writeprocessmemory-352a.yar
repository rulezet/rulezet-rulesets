rule TTP_XOR_WriteProcessMemory_352a {
  strings:
    $key_352a = { 62 58 [2] 50 7a [2] 56 4f [2] 78 4f [2] 47 53 }

  condition:
    any of them
}