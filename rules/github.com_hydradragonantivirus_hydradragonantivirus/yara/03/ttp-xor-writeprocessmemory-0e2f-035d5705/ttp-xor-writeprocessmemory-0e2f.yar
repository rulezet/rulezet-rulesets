rule TTP_XOR_WriteProcessMemory_0e2f {
  strings:
    $key_0e2f = { 59 5d [2] 6b 7f [2] 6d 4a [2] 43 4a [2] 7c 56 }

  condition:
    any of them
}