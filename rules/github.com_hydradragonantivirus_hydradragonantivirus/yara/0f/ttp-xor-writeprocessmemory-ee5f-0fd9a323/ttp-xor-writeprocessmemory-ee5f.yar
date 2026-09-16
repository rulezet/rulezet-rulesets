rule TTP_XOR_WriteProcessMemory_ee5f {
  strings:
    $key_ee5f = { b9 2d [2] 8b 0f [2] 8d 3a [2] a3 3a [2] 9c 26 }

  condition:
    any of them
}