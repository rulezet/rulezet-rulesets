rule TTP_XOR_WriteProcessMemory_e42f {
  strings:
    $key_e42f = { b3 5d [2] 81 7f [2] 87 4a [2] a9 4a [2] 96 56 }

  condition:
    any of them
}