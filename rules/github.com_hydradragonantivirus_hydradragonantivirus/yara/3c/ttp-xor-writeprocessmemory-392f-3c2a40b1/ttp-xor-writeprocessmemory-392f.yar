rule TTP_XOR_WriteProcessMemory_392f {
  strings:
    $key_392f = { 6e 5d [2] 5c 7f [2] 5a 4a [2] 74 4a [2] 4b 56 }

  condition:
    any of them
}