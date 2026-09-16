rule TTP_XOR_WriteProcessMemory_3e5d {
  strings:
    $key_3e5d = { 69 2f [2] 5b 0d [2] 5d 38 [2] 73 38 [2] 4c 24 }

  condition:
    any of them
}