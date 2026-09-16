rule TTP_XOR_WriteProcessMemory_081f {
  strings:
    $key_081f = { 5f 6d [2] 6d 4f [2] 6b 7a [2] 45 7a [2] 7a 66 }

  condition:
    any of them
}