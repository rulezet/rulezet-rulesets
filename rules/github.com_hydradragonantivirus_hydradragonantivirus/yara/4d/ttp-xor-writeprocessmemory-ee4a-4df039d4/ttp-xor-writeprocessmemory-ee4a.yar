rule TTP_XOR_WriteProcessMemory_ee4a {
  strings:
    $key_ee4a = { b9 38 [2] 8b 1a [2] 8d 2f [2] a3 2f [2] 9c 33 }

  condition:
    any of them
}