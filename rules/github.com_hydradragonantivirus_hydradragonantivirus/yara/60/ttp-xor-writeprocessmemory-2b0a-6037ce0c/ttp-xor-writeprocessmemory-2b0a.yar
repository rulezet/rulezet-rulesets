rule TTP_XOR_WriteProcessMemory_2b0a {
  strings:
    $key_2b0a = { 7c 78 [2] 4e 5a [2] 48 6f [2] 66 6f [2] 59 73 }

  condition:
    any of them
}