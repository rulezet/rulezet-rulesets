rule TTP_XOR_WriteProcessMemory_0a2f {
  strings:
    $key_0a2f = { 5d 5d [2] 6f 7f [2] 69 4a [2] 47 4a [2] 78 56 }

  condition:
    any of them
}