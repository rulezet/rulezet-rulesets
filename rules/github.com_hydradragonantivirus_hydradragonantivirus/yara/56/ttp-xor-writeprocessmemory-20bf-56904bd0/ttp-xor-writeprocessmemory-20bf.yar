rule TTP_XOR_WriteProcessMemory_20bf {
  strings:
    $key_20bf = { 77 cd [2] 45 ef [2] 43 da [2] 6d da [2] 52 c6 }

  condition:
    any of them
}