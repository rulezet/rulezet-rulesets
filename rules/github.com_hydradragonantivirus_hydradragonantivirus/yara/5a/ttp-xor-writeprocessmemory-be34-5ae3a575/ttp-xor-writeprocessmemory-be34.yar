rule TTP_XOR_WriteProcessMemory_be34 {
  strings:
    $key_be34 = { e9 46 [2] db 64 [2] dd 51 [2] f3 51 [2] cc 4d }

  condition:
    any of them
}