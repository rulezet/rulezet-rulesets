rule TTP_XOR_WriteProcessMemory_681a {
  strings:
    $key_681a = { 3f 68 [2] 0d 4a [2] 0b 7f [2] 25 7f [2] 1a 63 }

  condition:
    any of them
}