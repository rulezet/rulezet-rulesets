rule TTP_XOR_WriteProcessMemory_275a {
  strings:
    $key_275a = { 70 28 [2] 42 0a [2] 44 3f [2] 6a 3f [2] 55 23 }

  condition:
    any of them
}