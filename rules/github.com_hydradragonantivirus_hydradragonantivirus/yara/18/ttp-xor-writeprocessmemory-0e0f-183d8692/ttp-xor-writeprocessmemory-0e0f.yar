rule TTP_XOR_WriteProcessMemory_0e0f {
  strings:
    $key_0e0f = { 59 7d [2] 6b 5f [2] 6d 6a [2] 43 6a [2] 7c 76 }

  condition:
    any of them
}