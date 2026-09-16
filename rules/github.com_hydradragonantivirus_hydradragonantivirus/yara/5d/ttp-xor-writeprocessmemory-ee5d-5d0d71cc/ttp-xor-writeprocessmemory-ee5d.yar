rule TTP_XOR_WriteProcessMemory_ee5d {
  strings:
    $key_ee5d = { b9 2f [2] 8b 0d [2] 8d 38 [2] a3 38 [2] 9c 24 }

  condition:
    any of them
}