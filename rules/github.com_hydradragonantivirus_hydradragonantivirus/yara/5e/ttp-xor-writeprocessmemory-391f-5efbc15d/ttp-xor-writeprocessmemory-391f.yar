rule TTP_XOR_WriteProcessMemory_391f {
  strings:
    $key_391f = { 6e 6d [2] 5c 4f [2] 5a 7a [2] 74 7a [2] 4b 66 }

  condition:
    any of them
}