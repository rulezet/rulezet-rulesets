rule TTP_XOR_WriteProcessMemory_ebbf {
  strings:
    $key_ebbf = { bc cd [2] 8e ef [2] 88 da [2] a6 da [2] 99 c6 }

  condition:
    any of them
}