rule TTP_XOR_WriteProcessMemory_360f {
  strings:
    $key_360f = { 61 7d [2] 53 5f [2] 55 6a [2] 7b 6a [2] 44 76 }

  condition:
    any of them
}