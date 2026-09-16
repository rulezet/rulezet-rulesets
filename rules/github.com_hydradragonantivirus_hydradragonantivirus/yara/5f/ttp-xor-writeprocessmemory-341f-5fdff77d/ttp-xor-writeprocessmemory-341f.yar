rule TTP_XOR_WriteProcessMemory_341f {
  strings:
    $key_341f = { 63 6d [2] 51 4f [2] 57 7a [2] 79 7a [2] 46 66 }

  condition:
    any of them
}