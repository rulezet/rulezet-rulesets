rule TTP_XOR_WriteProcessMemory_083f {
  strings:
    $key_083f = { 5f 4d [2] 6d 6f [2] 6b 5a [2] 45 5a [2] 7a 46 }

  condition:
    any of them
}