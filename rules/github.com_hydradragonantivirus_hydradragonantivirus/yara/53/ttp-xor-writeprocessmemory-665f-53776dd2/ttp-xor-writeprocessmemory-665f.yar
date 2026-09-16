rule TTP_XOR_WriteProcessMemory_665f {
  strings:
    $key_665f = { 31 2d [2] 03 0f [2] 05 3a [2] 2b 3a [2] 14 26 }

  condition:
    any of them
}