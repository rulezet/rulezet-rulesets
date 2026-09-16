rule TTP_XOR_WriteProcessMemory_861f {
  strings:
    $key_861f = { d1 6d [2] e3 4f [2] e5 7a [2] cb 7a [2] f4 66 }

  condition:
    any of them
}