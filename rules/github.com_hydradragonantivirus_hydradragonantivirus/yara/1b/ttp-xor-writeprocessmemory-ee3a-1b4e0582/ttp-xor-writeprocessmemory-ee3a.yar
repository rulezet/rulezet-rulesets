rule TTP_XOR_WriteProcessMemory_ee3a {
  strings:
    $key_ee3a = { b9 48 [2] 8b 6a [2] 8d 5f [2] a3 5f [2] 9c 43 }

  condition:
    any of them
}