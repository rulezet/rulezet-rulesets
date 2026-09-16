rule TTP_XOR_WriteProcessMemory_021f {
  strings:
    $key_021f = { 55 6d [2] 67 4f [2] 61 7a [2] 4f 7a [2] 70 66 }

  condition:
    any of them
}