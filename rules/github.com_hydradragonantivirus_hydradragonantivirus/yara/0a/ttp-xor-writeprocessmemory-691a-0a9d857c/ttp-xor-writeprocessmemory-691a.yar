rule TTP_XOR_WriteProcessMemory_691a {
  strings:
    $key_691a = { 3e 68 [2] 0c 4a [2] 0a 7f [2] 24 7f [2] 1b 63 }

  condition:
    any of them
}