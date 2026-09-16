rule TTP_XOR_WriteProcessMemory_3c3f {
  strings:
    $key_3c3f = { 6b 4d [2] 59 6f [2] 5f 5a [2] 71 5a [2] 4e 46 }

  condition:
    any of them
}