rule TTP_XOR_WriteProcessMemory_f508 {
  strings:
    $key_f508 = { a2 7a [2] 90 58 [2] 96 6d [2] b8 6d [2] 87 71 }

  condition:
    any of them
}