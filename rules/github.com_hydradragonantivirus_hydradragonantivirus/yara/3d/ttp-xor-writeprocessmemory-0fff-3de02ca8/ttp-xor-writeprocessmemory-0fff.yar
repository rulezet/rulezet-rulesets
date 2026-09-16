rule TTP_XOR_WriteProcessMemory_0fff {
  strings:
    $key_0fff = { 58 8d [2] 6a af [2] 6c 9a [2] 42 9a [2] 7d 86 }

  condition:
    any of them
}