rule TTP_XOR_WriteProcessMemory_d02c {
  strings:
    $key_d02c = { 87 5e [2] b5 7c [2] b3 49 [2] 9d 49 [2] a2 55 }

  condition:
    any of them
}