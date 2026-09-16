rule TTP_XOR_WriteProcessMemory_417a {
  strings:
    $key_417a = { 16 08 [2] 24 2a [2] 22 1f [2] 0c 1f [2] 33 03 }

  condition:
    any of them
}