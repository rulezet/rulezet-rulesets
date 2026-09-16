rule TTP_XOR_WriteProcessMemory_f419 {
  strings:
    $key_f419 = { a3 6b [2] 91 49 [2] 97 7c [2] b9 7c [2] 86 60 }

  condition:
    any of them
}