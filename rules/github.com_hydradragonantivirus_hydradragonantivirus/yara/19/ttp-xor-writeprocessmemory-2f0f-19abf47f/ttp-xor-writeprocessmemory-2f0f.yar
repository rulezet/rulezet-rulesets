rule TTP_XOR_WriteProcessMemory_2f0f {
  strings:
    $key_2f0f = { 78 7d [2] 4a 5f [2] 4c 6a [2] 62 6a [2] 5d 76 }

  condition:
    any of them
}