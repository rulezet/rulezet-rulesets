rule TTP_XOR_WriteProcessMemory_f55c {
  strings:
    $key_f55c = { a2 2e [2] 90 0c [2] 96 39 [2] b8 39 [2] 87 25 }

  condition:
    any of them
}