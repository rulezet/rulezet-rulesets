rule TTP_XOR_WriteProcessMemory_2a3f {
  strings:
    $key_2a3f = { 7d 4d [2] 4f 6f [2] 49 5a [2] 67 5a [2] 58 46 }

  condition:
    any of them
}