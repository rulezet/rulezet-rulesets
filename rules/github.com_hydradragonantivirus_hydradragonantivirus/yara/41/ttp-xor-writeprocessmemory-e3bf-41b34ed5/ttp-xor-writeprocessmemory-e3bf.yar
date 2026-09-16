rule TTP_XOR_WriteProcessMemory_e3bf {
  strings:
    $key_e3bf = { b4 cd [2] 86 ef [2] 80 da [2] ae da [2] 91 c6 }

  condition:
    any of them
}