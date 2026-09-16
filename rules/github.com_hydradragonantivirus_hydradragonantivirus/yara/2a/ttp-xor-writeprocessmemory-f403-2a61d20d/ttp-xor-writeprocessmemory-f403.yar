rule TTP_XOR_WriteProcessMemory_f403 {
  strings:
    $key_f403 = { a3 71 [2] 91 53 [2] 97 66 [2] b9 66 [2] 86 7a }

  condition:
    any of them
}