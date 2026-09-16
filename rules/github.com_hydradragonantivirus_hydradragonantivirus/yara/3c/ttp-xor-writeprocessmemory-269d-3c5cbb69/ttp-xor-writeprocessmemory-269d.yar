rule TTP_XOR_WriteProcessMemory_269d {
  strings:
    $key_269d = { 71 ef [2] 43 cd [2] 45 f8 [2] 6b f8 [2] 54 e4 }

  condition:
    any of them
}