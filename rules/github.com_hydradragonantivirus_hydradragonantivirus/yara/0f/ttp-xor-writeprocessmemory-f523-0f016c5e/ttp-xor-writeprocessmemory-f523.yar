rule TTP_XOR_WriteProcessMemory_f523 {
  strings:
    $key_f523 = { a2 51 [2] 90 73 [2] 96 46 [2] b8 46 [2] 87 5a }

  condition:
    any of them
}