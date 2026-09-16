rule TTP_XOR_WriteProcessMemory_ee3f {
  strings:
    $key_ee3f = { b9 4d [2] 8b 6f [2] 8d 5a [2] a3 5a [2] 9c 46 }

  condition:
    any of them
}