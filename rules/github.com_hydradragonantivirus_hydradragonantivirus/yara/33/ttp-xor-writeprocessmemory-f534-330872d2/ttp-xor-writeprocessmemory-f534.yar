rule TTP_XOR_WriteProcessMemory_f534 {
  strings:
    $key_f534 = { a2 46 [2] 90 64 [2] 96 51 [2] b8 51 [2] 87 4d }

  condition:
    any of them
}