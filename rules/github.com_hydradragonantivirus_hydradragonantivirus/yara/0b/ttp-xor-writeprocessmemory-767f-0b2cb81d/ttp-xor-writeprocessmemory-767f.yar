rule TTP_XOR_WriteProcessMemory_767f {
  strings:
    $key_767f = { 21 0d [2] 13 2f [2] 15 1a [2] 3b 1a [2] 04 06 }

  condition:
    any of them
}