rule TTP_XOR_WriteProcessMemory_bedd {
  strings:
    $key_bedd = { e9 af [2] db 8d [2] dd b8 [2] f3 b8 [2] cc a4 }

  condition:
    any of them
}