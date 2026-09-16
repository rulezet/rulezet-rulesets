rule TTP_XOR_WriteProcessMemory_d069 {
  strings:
    $key_d069 = { 87 1b [2] b5 39 [2] b3 0c [2] 9d 0c [2] a2 10 }

  condition:
    any of them
}