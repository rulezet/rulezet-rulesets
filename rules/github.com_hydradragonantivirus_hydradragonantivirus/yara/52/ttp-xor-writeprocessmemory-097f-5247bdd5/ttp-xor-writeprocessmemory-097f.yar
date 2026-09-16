rule TTP_XOR_WriteProcessMemory_097f {
  strings:
    $key_097f = { 5e 0d [2] 6c 2f [2] 6a 1a [2] 44 1a [2] 7b 06 }

  condition:
    any of them
}