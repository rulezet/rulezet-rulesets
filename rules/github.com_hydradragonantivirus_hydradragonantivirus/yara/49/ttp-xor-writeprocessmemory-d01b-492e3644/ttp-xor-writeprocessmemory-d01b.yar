rule TTP_XOR_WriteProcessMemory_d01b {
  strings:
    $key_d01b = { 87 69 [2] b5 4b [2] b3 7e [2] 9d 7e [2] a2 62 }

  condition:
    any of them
}