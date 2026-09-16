rule TTP_XOR_WriteProcessMemory_610a {
  strings:
    $key_610a = { 36 78 [2] 04 5a [2] 02 6f [2] 2c 6f [2] 13 73 }

  condition:
    any of them
}