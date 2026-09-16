rule TTP_XOR_WriteProcessMemory_381f {
  strings:
    $key_381f = { 6f 6d [2] 5d 4f [2] 5b 7a [2] 75 7a [2] 4a 66 }

  condition:
    any of them
}