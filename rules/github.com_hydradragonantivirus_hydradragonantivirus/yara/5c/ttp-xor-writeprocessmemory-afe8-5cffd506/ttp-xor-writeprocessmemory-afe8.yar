rule TTP_XOR_WriteProcessMemory_afe8 {
  strings:
    $key_afe8 = { f8 9a [2] ca b8 [2] cc 8d [2] e2 8d [2] dd 91 }

  condition:
    any of them
}