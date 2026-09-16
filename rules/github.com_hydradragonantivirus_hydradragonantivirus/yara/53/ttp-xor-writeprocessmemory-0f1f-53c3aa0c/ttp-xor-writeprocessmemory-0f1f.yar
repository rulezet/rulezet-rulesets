rule TTP_XOR_WriteProcessMemory_0f1f {
  strings:
    $key_0f1f = { 58 6d [2] 6a 4f [2] 6c 7a [2] 42 7a [2] 7d 66 }

  condition:
    any of them
}