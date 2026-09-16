rule TTP_XOR_WriteProcessMemory_071f {
  strings:
    $key_071f = { 50 6d [2] 62 4f [2] 64 7a [2] 4a 7a [2] 75 66 }

  condition:
    any of them
}