rule TTP_XOR_WriteProcessMemory_c63c {
  strings:
    $key_c63c = { 91 4e [2] a3 6c [2] a5 59 [2] 8b 59 [2] b4 45 }

  condition:
    any of them
}