rule TTP_XOR_WriteProcessMemory_e36d {
  strings:
    $key_e36d = { b4 1f [2] 86 3d [2] 80 08 [2] ae 08 [2] 91 14 }

  condition:
    any of them
}