rule TTP_XOR_WriteProcessMemory_282f {
  strings:
    $key_282f = { 7f 5d [2] 4d 7f [2] 4b 4a [2] 65 4a [2] 5a 56 }

  condition:
    any of them
}