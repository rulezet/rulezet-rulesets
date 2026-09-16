rule TTP_XOR_WriteProcessMemory_c60c {
  strings:
    $key_c60c = { 91 7e [2] a3 5c [2] a5 69 [2] 8b 69 [2] b4 75 }

  condition:
    any of them
}