rule TTP_XOR_WriteProcessMemory_0f3f {
  strings:
    $key_0f3f = { 58 4d [2] 6a 6f [2] 6c 5a [2] 42 5a [2] 7d 46 }

  condition:
    any of them
}