rule TTP_XOR_WriteProcessMemory_edbf {
  strings:
    $key_edbf = { ba cd [2] 88 ef [2] 8e da [2] a0 da [2] 9f c6 }

  condition:
    any of them
}