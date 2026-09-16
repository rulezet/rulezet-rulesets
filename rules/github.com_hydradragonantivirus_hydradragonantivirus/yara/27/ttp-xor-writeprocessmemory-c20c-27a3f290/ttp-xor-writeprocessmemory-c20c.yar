rule TTP_XOR_WriteProcessMemory_c20c {
  strings:
    $key_c20c = { 95 7e [2] a7 5c [2] a1 69 [2] 8f 69 [2] b0 75 }

  condition:
    any of them
}