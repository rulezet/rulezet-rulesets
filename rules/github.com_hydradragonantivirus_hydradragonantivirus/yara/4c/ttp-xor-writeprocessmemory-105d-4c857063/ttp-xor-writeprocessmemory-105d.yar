rule TTP_XOR_WriteProcessMemory_105d {
  strings:
    $key_105d = { 47 2f [2] 75 0d [2] 73 38 [2] 5d 38 [2] 62 24 }

  condition:
    any of them
}