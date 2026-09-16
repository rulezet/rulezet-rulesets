rule TTP_XOR_WriteProcessMemory_5aea {
  strings:
    $key_5aea = { 0d 98 [2] 3f ba [2] 39 8f [2] 17 8f [2] 28 93 }

  condition:
    any of them
}