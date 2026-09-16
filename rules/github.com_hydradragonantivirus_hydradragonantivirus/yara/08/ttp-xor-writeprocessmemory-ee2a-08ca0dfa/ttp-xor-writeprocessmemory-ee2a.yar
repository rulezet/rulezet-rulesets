rule TTP_XOR_WriteProcessMemory_ee2a {
  strings:
    $key_ee2a = { b9 58 [2] 8b 7a [2] 8d 4f [2] a3 4f [2] 9c 53 }

  condition:
    any of them
}