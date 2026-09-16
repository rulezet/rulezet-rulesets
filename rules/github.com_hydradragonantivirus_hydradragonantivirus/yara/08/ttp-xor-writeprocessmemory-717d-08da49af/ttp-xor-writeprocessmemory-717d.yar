rule TTP_XOR_WriteProcessMemory_717d {
  strings:
    $key_717d = { 26 0f [2] 14 2d [2] 12 18 [2] 3c 18 [2] 03 04 }

  condition:
    any of them
}