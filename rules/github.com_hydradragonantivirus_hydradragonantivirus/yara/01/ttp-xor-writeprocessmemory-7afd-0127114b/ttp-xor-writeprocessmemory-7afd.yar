rule TTP_XOR_WriteProcessMemory_7afd {
  strings:
    $key_7afd = { 2d 8f [2] 1f ad [2] 19 98 [2] 37 98 [2] 08 84 }

  condition:
    any of them
}