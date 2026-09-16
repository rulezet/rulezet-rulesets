rule TTP_XOR_WriteProcessMemory_286f {
  strings:
    $key_286f = { 7f 1d [2] 4d 3f [2] 4b 0a [2] 65 0a [2] 5a 16 }

  condition:
    any of them
}