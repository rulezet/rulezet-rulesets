rule TTP_XOR_WriteProcessMemory_015d {
  strings:
    $key_015d = { 56 2f [2] 64 0d [2] 62 38 [2] 4c 38 [2] 73 24 }

  condition:
    any of them
}