rule TTP_XOR_WriteProcessMemory_2b3f {
  strings:
    $key_2b3f = { 7c 4d [2] 4e 6f [2] 48 5a [2] 66 5a [2] 59 46 }

  condition:
    any of them
}