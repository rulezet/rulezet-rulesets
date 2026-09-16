rule TTP_XOR_WriteProcessMemory_afee {
  strings:
    $key_afee = { f8 9c [2] ca be [2] cc 8b [2] e2 8b [2] dd 97 }

  condition:
    any of them
}