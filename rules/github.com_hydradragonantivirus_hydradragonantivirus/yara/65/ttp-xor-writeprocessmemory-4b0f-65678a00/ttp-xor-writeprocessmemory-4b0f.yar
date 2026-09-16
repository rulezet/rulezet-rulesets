rule TTP_XOR_WriteProcessMemory_4b0f {
  strings:
    $key_4b0f = { 1c 7d [2] 2e 5f [2] 28 6a [2] 06 6a [2] 39 76 }

  condition:
    any of them
}