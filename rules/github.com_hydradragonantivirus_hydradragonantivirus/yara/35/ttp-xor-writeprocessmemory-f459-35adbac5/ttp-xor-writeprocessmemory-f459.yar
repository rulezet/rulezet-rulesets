rule TTP_XOR_WriteProcessMemory_f459 {
  strings:
    $key_f459 = { a3 2b [2] 91 09 [2] 97 3c [2] b9 3c [2] 86 20 }

  condition:
    any of them
}