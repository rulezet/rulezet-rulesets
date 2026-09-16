rule TTP_XOR_WriteProcessMemory_c469 {
  strings:
    $key_c469 = { 93 1b [2] a1 39 [2] a7 0c [2] 89 0c [2] b6 10 }

  condition:
    any of them
}