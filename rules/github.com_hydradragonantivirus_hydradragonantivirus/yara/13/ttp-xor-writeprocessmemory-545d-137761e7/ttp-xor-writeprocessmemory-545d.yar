rule TTP_XOR_WriteProcessMemory_545d {
  strings:
    $key_545d = { 03 2f [2] 31 0d [2] 37 38 [2] 19 38 [2] 26 24 }

  condition:
    any of them
}