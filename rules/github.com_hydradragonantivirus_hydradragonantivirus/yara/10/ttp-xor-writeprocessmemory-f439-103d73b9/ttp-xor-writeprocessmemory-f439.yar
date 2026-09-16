rule TTP_XOR_WriteProcessMemory_f439 {
  strings:
    $key_f439 = { a3 4b [2] 91 69 [2] 97 5c [2] b9 5c [2] 86 40 }

  condition:
    any of them
}