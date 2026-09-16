rule TTP_XOR_WriteProcessMemory_623f {
  strings:
    $key_623f = { 35 4d [2] 07 6f [2] 01 5a [2] 2f 5a [2] 10 46 }

  condition:
    any of them
}