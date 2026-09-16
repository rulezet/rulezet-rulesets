rule TTP_XOR_WriteProcessMemory_ee5a {
  strings:
    $key_ee5a = { b9 28 [2] 8b 0a [2] 8d 3f [2] a3 3f [2] 9c 23 }

  condition:
    any of them
}