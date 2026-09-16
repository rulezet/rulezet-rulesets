rule TTP_XOR_WriteProcessMemory_e439 {
  strings:
    $key_e439 = { b3 4b [2] 81 69 [2] 87 5c [2] a9 5c [2] 96 40 }

  condition:
    any of them
}