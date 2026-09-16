rule TTP_XOR_WriteProcessMemory_2a0f {
  strings:
    $key_2a0f = { 7d 7d [2] 4f 5f [2] 49 6a [2] 67 6a [2] 58 76 }

  condition:
    any of them
}