rule TTP_XOR_WriteProcessMemory_c6ea {
  strings:
    $key_c6ea = { 91 98 [2] a3 ba [2] a5 8f [2] 8b 8f [2] b4 93 }

  condition:
    any of them
}