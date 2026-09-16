rule TTP_XOR_WriteProcessMemory_3f1f {
  strings:
    $key_3f1f = { 68 6d [2] 5a 4f [2] 5c 7a [2] 72 7a [2] 4d 66 }

  condition:
    any of them
}