rule TTP_XOR_WriteProcessMemory_625a {
  strings:
    $key_625a = { 35 28 [2] 07 0a [2] 01 3f [2] 2f 3f [2] 10 23 }

  condition:
    any of them
}