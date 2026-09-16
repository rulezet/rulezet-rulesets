rule TTP_XOR_WriteProcessMemory_2b1f {
  strings:
    $key_2b1f = { 7c 6d [2] 4e 4f [2] 48 7a [2] 66 7a [2] 59 66 }

  condition:
    any of them
}