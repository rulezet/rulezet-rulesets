rule TTP_XOR_WriteProcessMemory_e30d {
  strings:
    $key_e30d = { b4 7f [2] 86 5d [2] 80 68 [2] ae 68 [2] 91 74 }

  condition:
    any of them
}