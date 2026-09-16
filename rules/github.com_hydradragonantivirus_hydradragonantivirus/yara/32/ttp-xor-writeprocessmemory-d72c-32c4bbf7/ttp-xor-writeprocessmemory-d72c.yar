rule TTP_XOR_WriteProcessMemory_d72c {
  strings:
    $key_d72c = { 80 5e [2] b2 7c [2] b4 49 [2] 9a 49 [2] a5 55 }

  condition:
    any of them
}