rule TTP_XOR_WriteProcessMemory_ee6f {
  strings:
    $key_ee6f = { b9 1d [2] 8b 3f [2] 8d 0a [2] a3 0a [2] 9c 16 }

  condition:
    any of them
}