rule TTP_XOR_WriteProcessMemory_836f {
  strings:
    $key_836f = { d4 1d [2] e6 3f [2] e0 0a [2] ce 0a [2] f1 16 }

  condition:
    any of them
}