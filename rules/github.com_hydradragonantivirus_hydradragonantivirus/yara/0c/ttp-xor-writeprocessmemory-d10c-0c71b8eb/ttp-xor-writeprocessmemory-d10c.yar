rule TTP_XOR_WriteProcessMemory_d10c {
  strings:
    $key_d10c = { 86 7e [2] b4 5c [2] b2 69 [2] 9c 69 [2] a3 75 }

  condition:
    any of them
}